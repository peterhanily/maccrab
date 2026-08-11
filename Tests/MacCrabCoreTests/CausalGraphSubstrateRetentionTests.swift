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
import Darwin
import CSQLCipher
@testable import MacCrabCore
@testable import MacCrabAgentKit

private let SQLITE_TRANSIENT_SUBSTRATE_TEST = unsafeBitCast(
    OpaquePointer(bitPattern: -1)!, to: sqlite3_destructor_type.self)

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

    private final class TransitioningFreeSpaceProbe: @unchecked Sendable {
        private let lock = NSLock()
        private var lowReadsRemaining = Int.max
        private let low: Int64
        private let high: Int64

        init(low: Int64, high: Int64) {
            self.low = low
            self.high = high
        }

        func arm(lowReads: Int) {
            lock.lock()
            lowReadsRemaining = max(0, lowReads)
            lock.unlock()
        }

        func read() -> Int64 {
            lock.lock()
            defer { lock.unlock() }
            if lowReadsRemaining > 0 {
                lowReadsRemaining -= 1
                return low
            }
            return high
        }
    }

    private actor CascadeYieldGate {
        private var paused = false
        private var released = false
        private var pausedWaiter: CheckedContinuation<Void, Never>?
        private var releaseWaiter: CheckedContinuation<Void, Never>?

        func pauseOnce() async {
            guard !paused else { return }
            paused = true
            pausedWaiter?.resume()
            pausedWaiter = nil
            guard !released else { return }
            await withCheckedContinuation { continuation in
                releaseWaiter = continuation
            }
        }

        func waitUntilPaused() async {
            guard !paused else { return }
            await withCheckedContinuation { continuation in
                pausedWaiter = continuation
            }
        }

        func resume() {
            released = true
            releaseWaiter?.resume()
            releaseWaiter = nil
        }
    }

    private final class PageLimitFailureOnInstall: @unchecked Sendable {
        private let lock = NSLock()
        private var installCalls = 0
        private let failureCall: Int

        init(failureCall: Int) {
            self.failureCall = failureCall
        }

        func failure(
            for operation: CausalGraphPageLimitOperation
        ) -> CausalGraphInjectedSQLiteFailure? {
            guard operation == .installLimit else { return nil }
            lock.lock()
            installCalls += 1
            let shouldFail = installCalls == failureCall
            lock.unlock()
            return shouldFail
                ? CausalGraphInjectedSQLiteFailure(resultCode: SQLITE_IOERR)
                : nil
        }
    }

    private func executeRawSQL(path: String, sql: String) throws {
        var raw: OpaquePointer?
        guard sqlite3_open_v2(
            path,
            &raw,
            SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
            nil
        ) == SQLITE_OK, let raw else {
            throw CausalGraphStoreError.databaseOpenFailed("test raw open failed")
        }
        defer { sqlite3_close(raw) }
        guard sqlite3_exec(raw, sql, nil, nil, nil) == SQLITE_OK else {
            throw CausalGraphStoreError.stepFailed(
                String(cString: sqlite3_errmsg(raw)))
        }
    }

    private func rawPragma(path: String, name: String) throws -> Int64 {
        var raw: OpaquePointer?
        guard sqlite3_open_v2(
            path,
            &raw,
            SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX,
            nil
        ) == SQLITE_OK, let raw else {
            throw CausalGraphStoreError.databaseOpenFailed("test raw open failed")
        }
        defer { sqlite3_close(raw) }
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(raw, "PRAGMA \(name)", -1, &stmt, nil) == SQLITE_OK,
              let stmt else {
            throw CausalGraphStoreError.prepareFailed(
                String(cString: sqlite3_errmsg(raw)))
        }
        defer { sqlite3_finalize(stmt) }
        guard sqlite3_step(stmt) == SQLITE_ROW else {
            throw CausalGraphStoreError.stepFailed(
                String(cString: sqlite3_errmsg(raw)))
        }
        return sqlite3_column_int64(stmt, 0)
    }

    private func rawChildCount(
        path: String,
        table: String,
        traceID: String
    ) throws -> Int64 {
        var raw: OpaquePointer?
        guard sqlite3_open_v2(
            path,
            &raw,
            SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX,
            nil
        ) == SQLITE_OK, let raw else {
            throw CausalGraphStoreError.databaseOpenFailed("test raw open failed")
        }
        defer { sqlite3_close(raw) }
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(
            raw,
            "SELECT COUNT(*) FROM \(table) WHERE trace_id = ?1",
            -1,
            &stmt,
            nil
        ) == SQLITE_OK, let stmt else {
            throw CausalGraphStoreError.prepareFailed(
                String(cString: sqlite3_errmsg(raw)))
        }
        defer { sqlite3_finalize(stmt) }
        sqlite3_bind_text(stmt, 1, traceID, -1, SQLITE_TRANSIENT_SUBSTRATE_TEST)
        guard sqlite3_step(stmt) == SQLITE_ROW else {
            throw CausalGraphStoreError.stepFailed(
                String(cString: sqlite3_errmsg(raw)))
        }
        return sqlite3_column_int64(stmt, 0)
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

    private func startupTrace(
        _ id: String,
        updatedAt: Date,
        createdAt: Date? = nil,
        policyPayloadBytes: Int
    ) -> Trace {
        Trace(
            id: id,
            title: "Startup recovery test",
            anchorEventId: "event-\(id)",
            rootEntityId: nil,
            severity: "high",
            confidence: 1,
            createdAt: createdAt ?? updatedAt,
            updatedAt: updatedAt,
            daemonVersion: "test",
            rulesetVersion: "test",
            policyId: "default",
            policyVersion: "1",
            policySha256: "test",
            policySnapshotJson: String(repeating: "x", count: policyPayloadBytes),
            traceSigningKeyMode: "filesystem_degraded",
            replayScope: "declared_deterministic_subset",
            attributionOverridePolicy:
                "include_as_human_annotation_do_not_apply_by_default"
        )
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

    // v1.21.6-rc.12 regression. `recoverStorageBudget` deletes only inside the cutoffs
    // its CALLER supplies, and the daemon supplied the configured retention —
    // 90 days by default — plus a 1-hour orphan window. A store whose fill rate
    // is set by event volume reaches its cap in hours, so nothing was ever old
    // enough to qualify: on an installed rc.7 host the 300s timer reclaimed
    // exactly zero rows for two hours while the substrate sat pinned at its
    // admission threshold and shed 2,753,096 events, with 62 MB of its cap
    // unused. The bug is not that the sweep is wrong — it is that a time-only
    // window cannot bound a volume-driven store. Prove both halves.
    @Test("A volume-filled substrate is unreachable by the configured window, reachable by a tightened one")
    func timeOnlyRetentionCannotBoundAVolumeFilledSubstrate() async throws {
        let (store, path) = try await makeStore()
        defer { try? FileManager.default.removeItem(at: path) }

        // Everything is RECENT — the shape of a store that filled in hours.
        let now = Date(timeIntervalSince1970: 1_800_000_000)
        let minutesAgo = now.addingTimeInterval(-20 * 60)
        for i in 0..<40 {
            try await store.upsertEntity(ent("v\(i)", lastSeen: minutesAgo))
        }
        for i in 0..<39 {
            try await store.upsertEdge(edg("ve\(i)", from: "v\(i)", to: "v\(i + 1)", lastSeen: minutesAgo))
        }

        // What the daemon actually passed: retention 90 days, orphans 1 hour.
        let configured = try await store.recoverStorageBudget(
            retentionCutoff: now.addingTimeInterval(-90 * 86_400),
            orphanCutoff: now.addingTimeInterval(-3_600)
        )
        #expect(configured.edgesDeleted == 0 && configured.entitiesDeleted == 0,
                "the configured window must reclaim nothing here — this is the shipped bug")

        // The tightened rung the timer now falls back to. Anything older than
        // 10 minutes is eligible, so the 20-minute-old substrate is reachable.
        let tightened = try await store.recoverStorageBudget(
            retentionCutoff: now.addingTimeInterval(-600),
            orphanCutoff: now.addingTimeInterval(-600)
        )
        #expect(tightened.edgesDeleted > 0 || tightened.entitiesDeleted > 0,
                "a tightened window must reclaim what the configured one could not")

        await store.close()
    }

    @Test("Post-pass backlog keeps bounded recovery on the same cutoff despite progress")
    func boundedRecoveryReportsRemainingEligibleBacklog() async throws {
        let (store, path) = try await makeStore()
        defer { try? FileManager.default.removeItem(at: path) }

        for index in 0..<257 {
            try await store.upsertEntity(ent("old-\(index)", lastSeen: old))
        }
        try await store.upsertEntity(ent("recent-sentinel", lastSeen: recent))

        let first = try await store.recoverStorageBudget(
            retentionCutoff: cutoff,
            orphanCutoff: cutoff,
            maxTraceDeletes: 0,
            maxTraceChildRows: 0,
            maxGraphDeletesPerTable: 64,
            maxVacuumPages: 0
        )
        #expect(first.entitiesDeleted == 64)
        #expect(first.traceBacklogRemaining == false)
        #expect(first.orphanBacklogRemaining == true)
        #expect(first.eligibleBacklogRemaining == true,
                "making progress must not be mistaken for exhausting this cutoff")

        var result = first
        for _ in 0..<5 where result.eligibleBacklogRemaining != false {
            result = try await store.recoverStorageBudget(
                retentionCutoff: cutoff,
                orphanCutoff: cutoff,
                maxTraceDeletes: 0,
                maxTraceChildRows: 0,
                maxGraphDeletesPerTable: 64,
                maxVacuumPages: 0
            )
        }
        #expect(result.eligibleBacklogRemaining == false)
        #expect(try await store.entity(id: "old-256") == nil)
        #expect(try await store.entity(id: "recent-sentinel") != nil,
                "bounded convergence must preserve rows newer than the cutoff")
        await store.close()
    }

    @Test("Startup drains an inherited blocked store through rungs and bounded quanta")
    func startupRecoveryRestoresWritableAdmissionBeforeProducers() async throws {
        let (store, url) = try await makeStore()
        defer {
            for suffix in ["", "-wal", "-shm", "-journal"] {
                try? FileManager.default.removeItem(atPath: url.path + suffix)
            }
        }
        let now = Date(timeIntervalSince1970: 2_000_000_000)
        let expired = now.addingTimeInterval(-48 * 3_600)
        for index in 0..<320 {
            try await store.saveTrace(
                startupTrace(
                    "startup-old-\(index)",
                    updatedAt: expired,
                    policyPayloadBytes: 28 * 1_024
                ),
                members: []
            )
        }
        try await store.saveTrace(
            startupTrace(
                "startup-recent-sentinel",
                updatedAt: now.addingTimeInterval(-30 * 60),
                policyPayloadBytes: 1_024
            ),
            members: []
        )
        #expect(await store.walCheckpointTruncate())
        let footprint = try #require(await store.storageFootprintBytes())
        let reserve: Int64 = 8 * 1_048_576
        let blocked = await store.updateStorageAdmission(
            maxFootprintBytes: footprint + reserve - 1,
            freeSpaceFloorBytes: nil,
            transactionReserveBytes: reserve
        )
        #expect(blocked.blocked)

        let result = await store.recoverStorageBeforeProducers(
            configuredRetentionHours: 7 * 24,
            cutoffRungs: DaemonTimers.tracegraphRecoveryCutoffHours,
            now: now,
            maximumPasses: 16
        )

        #expect(result.disposition == .writable)
        #expect(result.normalWriteAdmissionRestored)
        #expect(result.writableBeforeProducers)
        #expect(Array(result.attemptedCutoffHours.prefix(3)) == [168, 72, 24])
        #expect(result.attemptedCutoffHours.filter { $0 == 24 }.count >= 2,
                "more than one bounded 256-trace quantum must drain at the same rung")
        #expect(result.finalAdmission?.recoveryDeficitBytes == 0)
        #expect(result.finalAdmission?.blocked == false)
        #expect(try await store.loadTrace(id: "startup-old-0") == nil)
        #expect(try await store.traceCount() < 321,
                "startup should reclaim only enough old evidence to cross the target")
        #expect(try await store.loadTrace(id: "startup-recent-sentinel") != nil,
                "startup convergence must preserve the protected recent trace")
        await store.close()
    }

    @Test("Startup proactively drains an unlatched rc.11 near-threshold store")
    func startupRecoveryDoesNotTrustAResetFootprintLatch() async throws {
        let (store, url) = try await makeStore()
        defer {
            for suffix in ["", "-wal", "-shm", "-journal"] {
                try? FileManager.default.removeItem(atPath: url.path + suffix)
            }
        }
        let now = Date(timeIntervalSince1970: 2_000_100_000)
        let expired = now.addingTimeInterval(-48 * 3_600)
        for index in 0..<240 {
            try await store.saveTrace(
                startupTrace(
                    "startup-proactive-\(index)",
                    updatedAt: expired,
                    policyPayloadBytes: 32 * 1_024
                ),
                members: []
            )
        }
        #expect(await store.walCheckpointTruncate())
        let footprint = try #require(await store.storageFootprintBytes())
        let mib: Int64 = 1_048_576
        let reserve = 8 * mib
        let threshold = footprint + 2 * mib
        let initial = await store.updateStorageAdmission(
            maxFootprintBytes: threshold + reserve,
            freeSpaceFloorBytes: nil,
            transactionReserveBytes: reserve
        )
        #expect(!initial.blocked, "restart must begin with no inherited in-memory latch")
        #expect((initial.footprintBytes ?? -1)
                >= (initial.proactiveRecoveryThresholdBytes ?? Int64.max))
        #expect((initial.recoveryDeficitBytes ?? 0) > 0)

        let result = await store.recoverStorageBeforeProducers(
            configuredRetentionHours: 7 * 24,
            cutoffRungs: DaemonTimers.tracegraphRecoveryCutoffHours,
            now: now,
            maximumPasses: 16
        )

        #expect(result.disposition == .writable)
        #expect(!result.initiallyBlocked)
        #expect(result.passes > 0,
                "an unlatched store at the proactive boundary still needs startup recovery")
        #expect(result.writableBeforeProducers)
        #expect(result.finalAdmission?.recoveryDeficitBytes == 0,
                "writable is insufficient until the durable low watermark is crossed")
        #expect(try await store.loadTrace(id: "startup-proactive-0") == nil)
        await store.close()
    }

    @Test("Startup returns typed non-convergence instead of deleting the protected hour")
    func startupRecoveryFailsClosedAtRecentEvidenceFloor() async throws {
        let (store, url) = try await makeStore()
        defer {
            for suffix in ["", "-wal", "-shm", "-journal"] {
                try? FileManager.default.removeItem(atPath: url.path + suffix)
            }
        }
        let now = Date(timeIntervalSince1970: 2_000_200_000)
        let protected = now.addingTimeInterval(-30 * 60)
        for index in 0..<220 {
            try await store.saveTrace(
                startupTrace(
                    "startup-protected-\(index)",
                    updatedAt: protected,
                    policyPayloadBytes: 40 * 1_024
                ),
                members: []
            )
        }
        #expect(await store.walCheckpointTruncate())
        let footprint = try #require(await store.storageFootprintBytes())
        let reserve: Int64 = 8 * 1_048_576
        let initial = await store.updateStorageAdmission(
            maxFootprintBytes: footprint + reserve - 1,
            freeSpaceFloorBytes: nil,
            transactionReserveBytes: reserve
        )
        #expect(initial.blocked)

        let result = await store.recoverStorageBeforeProducers(
            configuredRetentionHours: 7 * 24,
            cutoffRungs: DaemonTimers.tracegraphRecoveryCutoffHours,
            now: now,
            maximumPasses: 16
        )

        #expect(result.disposition == .nonconverged(.protectedEvidenceFloor))
        #expect(!result.writableBeforeProducers)
        #expect(result.attemptedCutoffHours == [168, 72, 24, 6, 1])
        #expect(result.finalAdmission?.blocked == true)
        #expect(try await store.loadTrace(id: "startup-protected-0") != nil)
        #expect(try await store.loadTrace(id: "startup-protected-219") != nil,
                "no trace newer than the one-hour floor may be deleted")
        await store.close()
    }

    @Test("Low-space startup preserves eligible rows when delete reserve is unavailable")
    func startupLowSpaceRecoveryDoesNotDeleteToRecoverFreeSpace() async throws {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("tracegraph-low-space-\(UUID().uuidString).db")
        defer {
            for suffix in ["", "-wal", "-shm", "-journal"] {
                try? FileManager.default.removeItem(atPath: url.path + suffix)
            }
        }
        let mib: Int64 = 1_048_576
        // Ordinary/recovery mutations need floor + 8 MiB reserve. A checkpoint
        // may still drain a small WAL here, but DELETE cannot create free space
        // and must not consume the remaining margin.
        let store = try await SQLiteCausalGraphStore(
            databasePath: url.path,
            freeSpaceProbe: { _ in 2 * mib }
        )
        let now = Date(timeIntervalSince1970: 2_000_300_000)
        let expired = now.addingTimeInterval(-48 * 3_600)
        for index in 0..<300 {
            try await store.saveTrace(
                startupTrace(
                    "startup-low-space-\(index)",
                    updatedAt: expired,
                    policyPayloadBytes: 256
                ),
                members: []
            )
        }
        try await store.saveTrace(
            startupTrace(
                "startup-low-space-recent",
                updatedAt: now.addingTimeInterval(-30 * 60),
                policyPayloadBytes: 256
            ),
            members: []
        )
        #expect(await store.walCheckpointTruncate())
        let footprint = try #require(await store.storageFootprintBytes())
        let initial = await store.updateStorageAdmission(
            maxFootprintBytes: footprint + 64 * mib,
            freeSpaceFloorBytes: mib,
            transactionReserveBytes: 8 * mib
        )
        #expect(initial.blocked)
        #expect(initial.reason == .lowFreeSpace)
        #expect(initial.recoveryDeficitBytes == 0)

        let result = await store.recoverStorageBeforeProducers(
            configuredRetentionHours: 7 * 24,
            cutoffRungs: DaemonTimers.tracegraphRecoveryCutoffHours,
            now: now,
            maximumPasses: 16
        )

        #expect(result.disposition == .nonconverged(.noRecoverableProgress))
        #expect(result.attemptedCutoffHours == [168, 72, 24],
                "empty coarse rungs may advance, but the first eligible low-space rung must not delete")
        #expect(result.lastRecovery?.tracesDeleted == 0)
        #expect(result.lastRecovery?.traceChildRowsDeleted == 0)
        #expect(try await store.loadTrace(id: "startup-low-space-0") != nil)
        #expect(try await store.loadTrace(id: "startup-low-space-299") != nil,
                "low free space must preserve even otherwise-eligible evidence")
        #expect(try await store.loadTrace(id: "startup-low-space-recent") != nil)
        #expect(result.finalAdmission?.reason == .lowFreeSpace)
        await store.close()
    }

    @Test("Floor-only startup accepts a fresh healthy ordinary-admission probe")
    func startupFloorOnlyLowSpaceCanRecoverWithoutAByteTarget() async throws {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("tracegraph-floor-only-\(UUID().uuidString).db")
        defer {
            for suffix in ["", "-wal", "-shm", "-journal"] {
                try? FileManager.default.removeItem(atPath: url.path + suffix)
            }
        }
        let mib: Int64 = 1_048_576
        let free = TransitioningFreeSpaceProbe(low: 2 * mib, high: 64 * mib)
        let store = try await SQLiteCausalGraphStore(
            databasePath: url.path,
            freeSpaceProbe: { _ in free.read() }
        )
        let now = Date(timeIntervalSince1970: 2_000_400_000)
        try await store.saveTrace(
            startupTrace(
                "floor-only-old",
                updatedAt: now.addingTimeInterval(-48 * 3_600),
                policyPayloadBytes: 16 * 1_024
            ),
            members: []
        )
        let initial = await store.updateStorageAdmission(
            maxFootprintBytes: nil,
            freeSpaceFloorBytes: mib,
            transactionReserveBytes: 8 * mib
        )
        #expect(initial.blocked)
        #expect(initial.reason == .lowFreeSpace)
        #expect(initial.resumeBelowBytes == nil)
        #expect(initial.recoveryDeficitBytes == nil)

        // Keep the initial update and first checkpoint probes low, then model
        // an operator/APFS cleanup restoring ordinary space during the bounded
        // startup loop. A nil byte target is legitimate for this floor-only
        // policy and must not be called a measurement failure.
        free.arm(lowReads: 3)
        let result = await store.recoverStorageBeforeProducers(
            configuredRetentionHours: 7 * 24,
            cutoffRungs: [72, 24, 6, 1],
            now: now,
            maximumPasses: 8
        )

        #expect(result.disposition == .writable)
        #expect(result.normalWriteAdmissionRestored)
        #expect(result.writableBeforeProducers)
        #expect(result.finalAdmission?.resumeBelowBytes == nil)
        #expect(result.finalAdmission?.recoveryDeficitBytes == nil)
        #expect(result.finalAdmission?.blocked == false)
        #expect(result.lastRecovery?.tracesDeleted == 0)
        #expect(try await store.loadTrace(id: "floor-only-old") != nil,
                "checkpoint/free-space recovery must not delete old evidence")
        await store.close()
    }

    @Test("Startup preserves every form of recent timed child evidence")
    func startupRecoveryUsesEffectiveTraceActivityForInheritedRows() async throws {
        let (bootstrap, url) = try await makeStore()
        defer {
            for suffix in ["", "-wal", "-shm", "-journal"] {
                try? FileManager.default.removeItem(atPath: url.path + suffix)
            }
        }
        let now = Date(timeIntervalSince1970: 2_000_500_000)
        let old = now.addingTimeInterval(-48 * 3_600)
        let recent = now.addingTimeInterval(-30 * 60)
        let protectedIDs = [
            "recent-created",
            "recent-membership",
            "recent-rule-hit",
            "recent-replay-start",
            "recent-replay-complete",
            "recent-hash",
        ]
        try await bootstrap.saveTrace(
            startupTrace(
                "recent-created",
                updatedAt: old,
                createdAt: recent,
                policyPayloadBytes: 512
            ),
            members: []
        )
        try await bootstrap.saveTrace(
            startupTrace(
                "recent-membership", updatedAt: old, policyPayloadBytes: 512),
            members: [
                TraceMembership(
                    traceId: "recent-membership",
                    entityId: "inherited-member",
                    role: "evidence",
                    addedAt: recent
                ),
            ]
        )
        try await bootstrap.saveTrace(
            startupTrace(
                "recent-rule-hit", updatedAt: old, policyPayloadBytes: 512),
            members: []
        )
        try await bootstrap.recordRuleHit(TraceRuleHit(
            id: "recent-hit",
            traceId: "recent-rule-hit",
            ruleId: "test",
            ruleTitle: "Recent inherited hit",
            ruleVersion: "1",
            severity: "high",
            matchedAt: recent,
            explanationJson: "{}"
        ))
        try await bootstrap.saveTrace(
            startupTrace(
                "recent-replay-start", updatedAt: old, policyPayloadBytes: 512),
            members: []
        )
        try await bootstrap.recordReplayRun(TraceReplayRun(
            id: "recent-start-run",
            traceId: "recent-replay-start",
            bundleId: "bundle",
            rulesetVersion: "1",
            daemonVersion: "1",
            normalizationVersion: "1",
            startedAt: recent,
            completedAt: nil,
            deterministic: true,
            resultJson: "{}"
        ))
        try await bootstrap.saveTrace(
            startupTrace(
                "recent-replay-complete", updatedAt: old, policyPayloadBytes: 512),
            members: []
        )
        try await bootstrap.recordReplayRun(TraceReplayRun(
            id: "recent-complete-run",
            traceId: "recent-replay-complete",
            bundleId: "bundle",
            rulesetVersion: "1",
            daemonVersion: "1",
            normalizationVersion: "1",
            startedAt: old,
            completedAt: recent,
            deterministic: true,
            resultJson: "{}"
        ))
        try await bootstrap.saveTrace(
            startupTrace(
                "recent-hash", updatedAt: old, policyPayloadBytes: 512),
            members: []
        )
        try await bootstrap.appendHashChain(TraceHashChainEntry(
            id: "recent-chain",
            traceId: "recent-hash",
            sequenceNumber: 1,
            previousHash: nil,
            currentHash: "test",
            createdAt: recent
        ))

        // Enough genuinely old payload to force the startup path through the
        // 1h rung while retaining a healthy control for physical convergence.
        for index in 0..<320 {
            try await bootstrap.saveTrace(
                startupTrace(
                    "effective-old-\(index)",
                    updatedAt: old,
                    policyPayloadBytes: 32 * 1_024
                ),
                members: []
            )
        }
        #expect(await bootstrap.walCheckpointTruncate())
        await bootstrap.close()

        // Recreate inherited rc.11 parent drift: older builds did not advance
        // updated_at when timed children were appended. Keep the created-at
        // fixture recent; reset every child-backed parent to the old timestamp.
        let childBacked = protectedIDs.filter { $0 != "recent-created" }
            .map { "'\($0)'" }
            .joined(separator: ",")
        try executeRawSQL(
            path: url.path,
            sql: "UPDATE traces SET created_at = \(old.timeIntervalSince1970), updated_at = \(old.timeIntervalSince1970) WHERE id IN (\(childBacked)); UPDATE traces SET updated_at = \(old.timeIntervalSince1970) WHERE id = 'recent-created';"
        )

        let store = try await SQLiteCausalGraphStore(databasePath: url.path)
        #expect(await store.walCheckpointTruncate())
        let footprint = try #require(await store.storageFootprintBytes())
        let reserve: Int64 = 8 * 1_048_576
        let initial = await store.updateStorageAdmission(
            maxFootprintBytes: footprint + reserve - 1,
            freeSpaceFloorBytes: nil,
            transactionReserveBytes: reserve
        )
        #expect(initial.blocked)

        let result = await store.recoverStorageBeforeProducers(
            configuredRetentionHours: 7 * 24,
            cutoffRungs: [72, 24, 6, 1],
            now: now,
            maximumPasses: 20
        )
        #expect(result.writableBeforeProducers)
        #expect(result.attemptedCutoffHours.contains(24))
        #expect(try await store.loadTrace(id: "effective-old-0") == nil)
        for id in protectedIDs {
            #expect(try await store.loadTrace(id: id) != nil,
                    "effective activity must preserve \(id)")
        }
        #expect(try rawChildCount(
            path: url.path,
            table: "trace_membership",
            traceID: "recent-membership"
        ) == 1)
        #expect(try rawChildCount(
            path: url.path,
            table: "trace_rule_hits",
            traceID: "recent-rule-hit"
        ) == 1)
        #expect(try rawChildCount(
            path: url.path,
            table: "trace_replay_runs",
            traceID: "recent-replay-start"
        ) == 1)
        #expect(try rawChildCount(
            path: url.path,
            table: "trace_replay_runs",
            traceID: "recent-replay-complete"
        ) == 1)
        #expect(try rawChildCount(
            path: url.path,
            table: "trace_hash_chain",
            traceID: "recent-hash"
        ) == 1)
        await store.close()
    }

    @Test("A recent child added at a cascade yield protects the trace")
    func cascadeRevalidatesEffectiveActivityAfterActorYield() async throws {
        let path = FileManager.default.temporaryDirectory
            .appendingPathComponent("tracegraph-cascade-race-\(UUID().uuidString).db")
        defer {
            for suffix in ["", "-wal", "-shm", "-journal"] {
                try? FileManager.default.removeItem(atPath: path.path + suffix)
            }
        }
        let gate = CascadeYieldGate()
        let store = try await SQLiteCausalGraphStore(
            databasePath: path.path,
            cascadeYieldHook: { await gate.pauseOnce() }
        )
        let traceID = "yield-protected"
        let memberships = (0..<600).map { index in
            TraceMembership(
                traceId: traceID,
                entityId: "old-member-\(index)",
                role: "context",
                layer: "context",
                addedAt: old
            )
        }
        try await store.saveTrace(
            startupTrace(traceID, updatedAt: old, policyPayloadBytes: 256),
            members: memberships
        )

        let pruning = Task {
            try await store.pruneTraces(olderThan: cutoff)
        }
        await gate.waitUntilPaused()
        do {
            try await store.recordRuleHit(TraceRuleHit(
                id: "fresh-yield-hit",
                traceId: traceID,
                ruleId: "fresh-rule",
                ruleTitle: "Fresh evidence during retention",
                ruleVersion: "1",
                severity: "high",
                matchedAt: recent,
                explanationJson: "{}"
            ))
        } catch {
            await gate.resume()
            _ = try? await pruning.value
            throw error
        }
        await gate.resume()

        #expect(try await pruning.value == 0)
        let surviving = try #require(await store.loadTrace(id: traceID))
        #expect(surviving.trace.updatedAt == recent)
        #expect(try rawChildCount(
            path: path.path,
            table: "trace_rule_hits",
            traceID: traceID
        ) == 1)
        #expect(try await store.memberCount(traceId: traceID) > 0,
                "the fresh child must stop later cascade quanta")
        await store.close()
    }

    @Test("Orphan recovery never deletes a surviving trace root entity")
    func recoveryProtectsRootEntityWithoutMembership() async throws {
        let (store, url) = try await makeStore()
        defer {
            for suffix in ["", "-wal", "-shm", "-journal"] {
                try? FileManager.default.removeItem(atPath: url.path + suffix)
            }
        }
        let now = Date(timeIntervalSince1970: 2_000_600_000)
        let root = ent("root-only", lastSeen: now.addingTimeInterval(-48 * 3_600))
        try await store.upsertEntity(root)
        let trace = Trace(
            id: "root-only-trace",
            title: "Root-only inherited trace",
            anchorEventId: "root-anchor",
            rootEntityId: root.id,
            severity: "high",
            confidence: 1,
            createdAt: now.addingTimeInterval(-30 * 60),
            updatedAt: now.addingTimeInterval(-30 * 60),
            daemonVersion: "test",
            rulesetVersion: "test",
            policyId: "default",
            policyVersion: "1",
            policySha256: "test",
            policySnapshotJson: "{}",
            traceSigningKeyMode: "filesystem_degraded",
            replayScope: "declared_deterministic_subset",
            attributionOverridePolicy:
                "include_as_human_annotation_do_not_apply_by_default"
        )
        try await store.saveTrace(trace, members: [])

        let recovery = try await store.recoverStorageBudget(
            retentionCutoff: now.addingTimeInterval(-3_600),
            orphanCutoff: now.addingTimeInterval(-3_600),
            maxTraceDeletes: 16,
            maxGraphDeletesPerTable: 16,
            maxVacuumPages: 16
        )
        #expect(recovery.entitiesDeleted == 0)
        #expect(try await store.entity(id: root.id) != nil)
        #expect(try await store.loadTrace(id: trace.id) != nil)
        await store.close()
    }

    @Test("Startup proof requires a live read-write SQLite handle")
    func startupRejectsClosedAndExplicitReadOnlyHandles() async throws {
        let (store, url) = try await makeStore()
        defer {
            for suffix in ["", "-wal", "-shm", "-journal"] {
                try? FileManager.default.removeItem(atPath: url.path + suffix)
            }
        }
        await store.close()
        let closed = await store.recoverStorageBeforeProducers(
            configuredRetentionHours: 7 * 24,
            cutoffRungs: [72, 24, 6, 1]
        )
        #expect(closed.disposition == .nonconverged(.writableHandleUnavailable))
        #expect(!closed.writableBeforeProducers)
        #expect(closed.finalAdmission?.writableHandle == false)

        let readOnly = try await SQLiteCausalGraphStore(
            databasePath: url.path,
            forceReadOnly: true
        )
        let readOnlyResult = await readOnly.recoverStorageBeforeProducers(
            configuredRetentionHours: 7 * 24,
            cutoffRungs: [72, 24, 6, 1]
        )
        #expect(readOnlyResult.disposition
                == .nonconverged(.writableHandleUnavailable))
        #expect(!readOnlyResult.writableBeforeProducers)
        #expect(readOnlyResult.finalAdmission?.writableHandle == false)
        await readOnly.close()
    }

    @Test("Startup verifies the configured page ceiling before claiming writable")
    func startupFailsClosedWhenFinalPageCeilingCannotBeReinstalled() async throws {
        let (bootstrap, url) = try await makeStore()
        defer {
            for suffix in ["", "-wal", "-shm", "-journal"] {
                try? FileManager.default.removeItem(atPath: url.path + suffix)
            }
        }
        await bootstrap.close()
        let failure = PageLimitFailureOnInstall(failureCall: 3)
        let store = try await SQLiteCausalGraphStore(
            databasePath: url.path,
            maxFootprintBytes: 64 * 1_048_576,
            transactionReserveBytes: 8 * 1_048_576,
            pageLimitFailureProbe: { failure.failure(for: $0) }
        )
        let result = await store.recoverStorageBeforeProducers(
            configuredRetentionHours: 7 * 24,
            cutoffRungs: [72, 24, 6, 1]
        )
        #expect(result.disposition == .nonconverged(.recoveryFailed))
        #expect(!result.writableBeforeProducers)
        #expect(result.failureDetail?.contains("max_page_count") == true)
        await store.close()
    }

    @Test("Implicit production read-only fallback cannot claim writable startup")
    func startupRejectsReadOnlyFallbackFromOrdinaryOpen() async throws {
        let (bootstrap, url) = try await makeStore()
        defer {
            _ = chmod(url.path, 0o600)
            for suffix in ["", "-wal", "-shm", "-journal"] {
                try? FileManager.default.removeItem(atPath: url.path + suffix)
            }
        }
        #expect(await bootstrap.walCheckpointTruncate())
        await bootstrap.close()
        #expect(chmod(url.path, 0o400) == 0)

        let fallback = try await SQLiteCausalGraphStore(databasePath: url.path)
        let openedAdmission = await fallback.storageAdmissionStatus()
        if openedAdmission.writableHandle {
            // Root/capability-elevated CI can still open an owner-0400 file
            // read-write even when access(2) reports otherwise, so this
            // environment cannot exercise non-root fallback. Explicit
            // forceReadOnly coverage above proves the gate.
            await fallback.close()
            return
        }
        let result = await fallback.recoverStorageBeforeProducers(
            configuredRetentionHours: 7 * 24,
            cutoffRungs: [72, 24, 6, 1]
        )
        #expect(result.disposition
                == .nonconverged(.writableHandleUnavailable))
        #expect(result.finalAdmission?.writableHandle == false)
        #expect(!result.writableBeforeProducers)
        await fallback.close()
    }

    @Test("Startup exhausts pre-existing freelist pages before deleting evidence")
    func startupVacuumOnlyPhaseCanConvergeWithoutLogicalDeletion() async throws {
        let (bootstrap, url) = try await makeStore()
        defer {
            for suffix in ["", "-wal", "-shm", "-journal"] {
                try? FileManager.default.removeItem(atPath: url.path + suffix)
            }
        }
        let now = Date(timeIntervalSince1970: 2_000_650_000)
        let old = now.addingTimeInterval(-48 * 3_600)
        for index in 0..<400 {
            try await bootstrap.saveTrace(
                startupTrace(
                    "vacuum-seed-\(index)", updatedAt: old,
                    policyPayloadBytes: 32 * 1_024
                ),
                members: []
            )
        }
        try await bootstrap.saveTrace(
            startupTrace(
                "vacuum-old-sentinel", updatedAt: old,
                policyPayloadBytes: 512
            ),
            members: []
        )
        try await bootstrap.upsertEntity(ent("vacuum-old-orphan", lastSeen: old))
        #expect(await bootstrap.walCheckpointTruncate())
        await bootstrap.close()
        try executeRawSQL(path: url.path, sql: """
            DELETE FROM traces WHERE id LIKE 'vacuum-seed-%';
            PRAGMA wal_checkpoint(TRUNCATE);
            """)
        let pageSize = try rawPragma(path: url.path, name: "page_size")
        let freelist = try rawPragma(path: url.path, name: "freelist_count")
        let reserve: Int64 = 8 * 1_048_576
        #expect(freelist * pageSize > reserve,
                "fixture must carry more than one vacuum quantum")
        let footprint = try #require(
            SQLiteCausalGraphStore.exactSQLiteFootprintBytes(
                databasePath: url.path
            )
        )
        let store = try await SQLiteCausalGraphStore(
            databasePath: url.path,
            maxFootprintBytes: footprint + reserve - 1,
            transactionReserveBytes: reserve
        )
        let result = await store.recoverStorageBeforeProducers(
            configuredRetentionHours: 7 * 24,
            cutoffRungs: [72, 24, 6, 1],
            now: now,
            maximumPasses: 8
        )
        #expect(result.writableBeforeProducers)
        #expect(result.passes >= 2,
                "more than one physical quantum should be required")
        #expect(result.lastRecovery?.tracesDeleted == 0)
        #expect(result.lastRecovery?.edgesDeleted == 0)
        #expect(result.lastRecovery?.entitiesDeleted == 0)
        #expect(try await store.loadTrace(id: "vacuum-old-sentinel") != nil)
        #expect(try await store.entity(id: "vacuum-old-orphan") != nil)
        await store.close()
    }

    @Test("Proactive mode-zero startup preserves rows for offline conversion")
    func startupModeZeroProactivePressureDoesNotDeleteLogicalEvidence() async throws {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("tracegraph-mode-zero-proactive-\(UUID().uuidString).db")
        defer {
            for suffix in ["", "-wal", "-shm", "-journal"] {
                try? FileManager.default.removeItem(atPath: url.path + suffix)
            }
        }
        try executeRawSQL(
            path: url.path,
            sql: "PRAGMA auto_vacuum = NONE; CREATE TABLE legacy_seed(value TEXT); INSERT INTO legacy_seed VALUES ('seed');"
        )
        let bootstrap = try await SQLiteCausalGraphStore(databasePath: url.path)
        #expect(await bootstrap.autoVacuumMode() == 0)
        let now = Date(timeIntervalSince1970: 2_000_700_000)
        try await bootstrap.saveTrace(
            startupTrace(
                "mode-zero-preserve",
                updatedAt: now.addingTimeInterval(-48 * 3_600),
                policyPayloadBytes: 64 * 1_024
            ),
            members: []
        )
        await bootstrap.close()

        let mib: Int64 = 1_048_576
        let store = try await SQLiteCausalGraphStore(
            databasePath: url.path,
            maxFootprintBytes: 16 * mib,
            transactionReserveBytes: 4 * mib,
            footprintProbe: { _ in 11 * mib }
        )
        let initial = await store.storageAdmissionStatus()
        #expect(!initial.blocked)
        #expect(initial.footprintBytes == initial.proactiveRecoveryThresholdBytes)
        #expect((initial.recoveryDeficitBytes ?? 0) > 0)

        let result = await store.recoverStorageBeforeProducers(
            configuredRetentionHours: 7 * 24,
            cutoffRungs: [72, 24, 6, 1],
            now: now,
            maximumPasses: 8
        )
        #expect(result.disposition
                == .nonconverged(.incrementalVacuumUnavailable))
        #expect(result.lastRecovery?.autoVacuumMode == 0)
        #expect(result.lastRecovery?.tracesDeleted == 0)
        #expect(result.lastRecovery?.traceChildRowsDeleted == 0)
        #expect(try await store.loadTrace(id: "mode-zero-preserve") != nil,
                "mode-zero proactive recovery must not trade evidence for zero shrink")
        await store.close()
    }

    @Test("Inherited auto-vacuum FULL store converges across bounded passes")
    func startupModeFullContinuesWhileDeleteCommitsShrinkTheFile() async throws {
        let (bootstrap, url) = try await makeStore()
        defer {
            for suffix in ["", "-wal", "-shm", "-journal"] {
                try? FileManager.default.removeItem(atPath: url.path + suffix)
            }
        }
        let now = Date(timeIntervalSince1970: 2_000_800_000)
        let expired = now.addingTimeInterval(-48 * 3_600)
        for index in 0..<400 {
            try await bootstrap.saveTrace(
                startupTrace(
                    "mode-full-old-\(index)",
                    updatedAt: expired,
                    policyPayloadBytes: 24 * 1_024
                ),
                members: []
            )
        }
        #expect(await bootstrap.walCheckpointTruncate())
        await bootstrap.close()
        try executeRawSQL(
            path: url.path,
            sql: "PRAGMA journal_mode = DELETE; PRAGMA auto_vacuum = FULL;"
        )
        #expect(try rawPragma(path: url.path, name: "auto_vacuum") == 1)
        let footprint = try #require(
            SQLiteCausalGraphStore.exactSQLiteFootprintBytes(
                databasePath: url.path
            )
        )
        let reserve: Int64 = 8 * 1_048_576
        let store = try await SQLiteCausalGraphStore(
            databasePath: url.path,
            maxFootprintBytes: footprint + reserve - 1,
            transactionReserveBytes: reserve
        )
        #expect((await store.storageAdmissionStatus()).blocked)
        #expect(await store.autoVacuumMode() == 1)

        let result = await store.recoverStorageBeforeProducers(
            configuredRetentionHours: 7 * 24,
            cutoffRungs: [72, 24, 6, 1],
            now: now,
            maximumPasses: 20
        )
        #expect(result.writableBeforeProducers)
        #expect(result.finalAdmission?.recoveryDeficitBytes == 0)
        #expect(result.lastRecovery?.autoVacuumMode == 1)
        #expect(try await store.loadTrace(id: "mode-full-old-0") == nil)

        // The failure-injection regression above proves startup reissues and
        // verifies the live daemon connection's final page ceiling. A second
        // SQLite connection reports its own max_page_count setting.
        await store.close()
    }

    @Test("Bootstrap fails closed on graph non-convergence before every producer marker")
    func bootstrapRequiresTraceGraphStartupProofBeforeIngestion() throws {
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let bootstrap = try String(
            contentsOf: root.appendingPathComponent(
                "Sources/MacCrabAgentKit/DaemonBootstrap.swift"
            ),
            encoding: .utf8
        )
        let setup = try String(
            contentsOf: root.appendingPathComponent(
                "Sources/MacCrabAgentKit/DaemonSetup.swift"
            ),
            encoding: .utf8
        )
        let recovery = try #require(setup.range(of:
            "recoverStorageBeforeProducers("
        ))
        let setupGuard = try #require(setup.range(of:
            "guard recovery.writableBeforeProducers"
        ))
        let activationBoundary = try #require(setup.range(of:
            "FINAL_PRE_INGESTION_STORAGE_ACTIVATION_BOUNDARY"
        ))
        let activationGraphProbe = try #require(setup.range(of:
            "activationCausalStore.storageAdmissionStatus()"
        ))
        let setupProducerMarkers = [
            "startupWorkLifecycle.submit(",
            "await mcpMonitor.start()",
            "await ultrasonicMonitor.start()",
            "if await fleet.start()",
            "await dnsCollector.start()",
            "await eventTapMonitor.start()",
            "await systemPolicyMonitor.start()",
            "await fsEventsCollector.start()",
            "ulCollector = try UnifiedLogCollector()",
            "collector = try ESCollector(",
            "await esloggerCollector!.start()",
            "await kdebug.start()",
            "for alert in bootstrapAlerts",
            "try await receiver.start()",
        ]
        #expect(recovery.lowerBound < setupGuard.lowerBound)
        #expect(setupGuard.lowerBound < activationBoundary.lowerBound)
        #expect(activationBoundary.lowerBound < activationGraphProbe.lowerBound)
        for marker in setupProducerMarkers {
            let producer = try #require(setup.range(of: marker))
            #expect(activationGraphProbe.lowerBound < producer.lowerBound,
                    "fresh TraceGraph activation proof must precede \(marker)")
        }

        let bootstrapProof = try #require(bootstrap.range(of:
            "let traceGraphStartupRecovery = state.causalStoreStartupRecovery"
        ))
        let failClosed = try #require(bootstrap.range(of:
            "guard traceGraphStartupRecovery.writableBeforeProducers"
        ))
        let banner = try #require(bootstrap.range(of:
            "await StartupBanner.print(state: state)"
        ))
        let monitors = try #require(bootstrap.range(of:
            "await MonitorTasks.start(state: state, supervisor: supervisor)"
        ))
        let network = try #require(bootstrap.range(of:
            "await state.networkCollector.start()"
        ))
        let tcc = try #require(bootstrap.range(of:
            "await state.tccMonitor.start()"
        ))
        let timers = try #require(bootstrap.range(of:
            "let timerHandles = DaemonTimers.start("
        ))
        let eventLoop = try #require(bootstrap.range(of:
            "await EventLoop.run("
        ))
        let sequenceCheckpoint = try #require(bootstrap.range(of:
            "startPeriodicCheckpointing("
        ))
        let storageErrorRefresh = try #require(bootstrap.range(of:
            "StorageErrorTracker.shared.refreshSnapshot()"
        ))
        #expect(bootstrapProof.lowerBound < failClosed.lowerBound)
        for producer in [
            sequenceCheckpoint, storageErrorRefresh, banner, monitors,
            network, tcc, timers, eventLoop,
        ] {
            #expect(failClosed.lowerBound < producer.lowerBound)
        }
        #expect(bootstrap.contains("phase: \"storage_not_ready\""))
        #expect(bootstrap.contains(
            "throw DaemonBootstrapError.preIngestionStorageNotReady"
        ))
        #expect(bootstrap.contains(
            "public static func prepare(printBanner: Bool = true) async throws"
        ))
        #expect(setup.contains("static func initialize() async throws"))
    }

    private func recoveryResult(
        deficit: Int64?,
        backlog: Bool?,
        pinned: Bool = false,
        rowsDeleted: Int = 0
    ) -> CausalGraphStorageRecoveryResult {
        CausalGraphStorageRecoveryResult(
            pinnedReader: pinned,
            tracesDeleted: 0,
            traceChildRowsDeleted: 0,
            edgesDeleted: 0,
            entitiesDeleted: rowsDeleted,
            vacuumPagesReclaimed: 0,
            footprintBeforeBytes: 200,
            footprintBytes: 190,
            autoVacuumMode: 2,
            recoveryTargetBytes: 100,
            recoveryDeficitBytes: deficit,
            traceBacklogRemaining: backlog,
            orphanBacklogRemaining: false,
            eligibleBacklogRemaining: backlog
        )
    }

    @Test("Recovery cadence advances only after post-pass backlog exhaustion")
    func recoveryCadenceUsesDeficitAndPostPassState() {
        let gate = TraceGraphRecoveryCadenceGate()
        let start = Date(timeIntervalSince1970: 2_000_000_000)
        #expect(gate.cutoffHoursIfShouldRun(
            blocked: true,
            footprintBytes: 200,
            proactiveThresholdBytes: 150,
            configuredRetentionHours: 90 * 24,
            now: start
        ) == 90 * 24)

        let progressWithBacklog = recoveryResult(
            deficit: 90,
            backlog: true,
            rowsDeleted: 2_000
        )
        #expect(gate.recordRecoveryOutcome(
            progressWithBacklog,
            configuredRetentionHours: 90 * 24,
            cutoffRungs: DaemonTimers.tracegraphRecoveryCutoffHours
        ) == .draining)
        #expect(gate.cutoffHoursIfShouldRun(
            blocked: true,
            footprintBytes: 190,
            proactiveThresholdBytes: 150,
            configuredRetentionHours: 90 * 24,
            now: start.addingTimeInterval(30)
        ) == 90 * 24,
                "row progress must not tighten while this cutoff still has backlog")

        #expect(gate.recordRecoveryOutcome(
            recoveryResult(deficit: 80, backlog: false, rowsDeleted: 1),
            configuredRetentionHours: 90 * 24,
            cutoffRungs: DaemonTimers.tracegraphRecoveryCutoffHours
        ) == .advanced(toHours: 72))
        #expect(gate.cutoffHoursIfShouldRun(
            blocked: true,
            footprintBytes: 180,
            proactiveThresholdBytes: 150,
            configuredRetentionHours: 90 * 24,
            now: start.addingTimeInterval(60)
        ) == 72)
    }

    @Test("Recovery cadence is proactive and stops tightening at one hour")
    func recoveryCadenceProtectsRecentEvidenceFloor() {
        let gate = TraceGraphRecoveryCadenceGate()
        let start = Date(timeIntervalSince1970: 2_000_000_100)
        #expect(gate.cutoffHoursIfShouldRun(
            blocked: false,
            footprintBytes: 150,
            proactiveThresholdBytes: 150,
            configuredRetentionHours: 90 * 24,
            now: start
        ) == 90 * 24, "near-high-water recovery must start before admission blocks")

        for expected in [72, 24, 6, 1] {
            #expect(gate.recordRecoveryOutcome(
                recoveryResult(deficit: 1, backlog: false),
                configuredRetentionHours: 90 * 24,
                cutoffRungs: DaemonTimers.tracegraphRecoveryCutoffHours
            ) == .advanced(toHours: expected))
        }
        #expect(gate.recordRecoveryOutcome(
            recoveryResult(deficit: 1, backlog: false),
            configuredRetentionHours: 90 * 24,
            cutoffRungs: DaemonTimers.tracegraphRecoveryCutoffHours
        ) == .evidenceFloorExhausted)
        #expect(gate.cutoffHoursIfShouldRun(
            blocked: true,
            footprintBytes: 151,
            proactiveThresholdBytes: 150,
            configuredRetentionHours: 90 * 24,
            now: start.addingTimeInterval(30)
        ) == nil, "an infeasible protected working set backs off instead of deleting <1h data")
        #expect(gate.cutoffHoursIfShouldRun(
            blocked: true,
            footprintBytes: 151,
            proactiveThresholdBytes: 150,
            configuredRetentionHours: 90 * 24,
            now: start.addingTimeInterval(300)
        ) == 1, "aging rows are rechecked at the protected floor")
    }

    @Test("Tightening rungs descend to a floor that protects the materialization window")
    func recoveryCutoffRungsAreOrderedAndFloored() {
        let rungs = DaemonTimers.tracegraphRecoveryCutoffHours
        #expect(!rungs.isEmpty)
        #expect(rungs == rungs.sorted(by: >), "rungs must go coarse -> fine")
        // One hour is >> the 5-minute trace materialization window, so a
        // tightened sweep can never delete the context of a trace still being
        // assembled. A rung below this would trade reported degradation for
        // silent destruction of the most recent graph.
        #expect((rungs.last ?? 0) >= 1, "the floor must stay clear of the 5-minute trace window")
    }
}
