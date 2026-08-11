import Testing
import Foundation
import Darwin
import CSQLCipher
@testable import MacCrabCore

private let SQLITE_TRANSIENT_TEST = unsafeBitCast(
    OpaquePointer(bitPattern: -1)!, to: sqlite3_destructor_type.self)

@Suite("TraceGraph: authoritative storage admission + bounded recovery")
struct CausalGraphStorageAdmissionTests {
    private static let mib: Int64 = 1_048_576

    private final class ProbeBox: @unchecked Sendable {
        private let lock = NSLock()
        private var stored: Int64?

        init(_ value: Int64?) { stored = value }

        func get() -> Int64? {
            lock.lock()
            defer { lock.unlock() }
            return stored
        }

        func set(_ value: Int64?) {
            lock.lock()
            stored = value
            lock.unlock()
        }
    }

    private final class FootprintMonitor: @unchecked Sendable {
        private let lock = NSLock()
        private var finished = false
        private var maximum: Int64 = 0

        func record(_ value: Int64) {
            lock.lock()
            maximum = max(maximum, value)
            lock.unlock()
        }

        func finish() {
            lock.lock()
            finished = true
            lock.unlock()
        }

        func snapshot() -> (finished: Bool, maximum: Int64) {
            lock.lock()
            defer { lock.unlock() }
            return (finished, maximum)
        }
    }

    private final class ReaderLease: @unchecked Sendable {
        private let lock = NSLock()
        private var db: OpaquePointer?

        init(path: String) throws {
            var handle: OpaquePointer?
            guard sqlite3_open_v2(
                path, &handle,
                SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX,
                nil
            ) == SQLITE_OK, let handle else {
                throw CausalGraphStoreError.databaseOpenFailed(
                    "test reader lease")
            }
            db = handle
            guard sqlite3_exec(handle, "BEGIN", nil, nil, nil) == SQLITE_OK else {
                release()
                throw CausalGraphStoreError.stepFailed("test reader BEGIN")
            }
            var stmt: OpaquePointer?
            guard sqlite3_prepare_v2(
                handle, "SELECT COUNT(*) FROM traces", -1, &stmt, nil
            ) == SQLITE_OK else {
                release()
                throw CausalGraphStoreError.prepareFailed("test reader SELECT")
            }
            defer { sqlite3_finalize(stmt) }
            guard sqlite3_step(stmt) == SQLITE_ROW else {
                release()
                throw CausalGraphStoreError.stepFailed("test reader snapshot")
            }
        }

        func release() {
            lock.lock()
            defer { lock.unlock() }
            guard let db else { return }
            _ = sqlite3_exec(db, "COMMIT", nil, nil, nil)
            sqlite3_close(db)
            self.db = nil
        }

        deinit { release() }
    }

    private static func tempPath(_ label: String) -> String {
        FileManager.default.temporaryDirectory
            .appendingPathComponent("tracegraph-admission-\(label)-\(UUID().uuidString).db")
            .path
    }

    private static func cleanup(_ path: String) {
        for suffix in ["", "-wal", "-shm", "-journal"] {
            try? FileManager.default.removeItem(atPath: path + suffix)
        }
    }

    private static func pragmaInt64(path: String, name: String) throws -> Int64 {
        var db: OpaquePointer?
        guard sqlite3_open_v2(
            path, &db, SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX, nil
        ) == SQLITE_OK, let db else {
            throw CausalGraphStoreError.databaseOpenFailed("test pragma connection")
        }
        defer { sqlite3_close(db) }
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, "PRAGMA \(name)", -1, &stmt, nil) == SQLITE_OK else {
            throw CausalGraphStoreError.prepareFailed("test pragma \(name)")
        }
        defer { sqlite3_finalize(stmt) }
        guard sqlite3_step(stmt) == SQLITE_ROW else {
            throw CausalGraphStoreError.stepFailed("test pragma \(name)")
        }
        return sqlite3_column_int64(stmt, 0)
    }

    private static func rawExec(path: String, sql: String) throws {
        var db: OpaquePointer?
        guard sqlite3_open_v2(
            path, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX, nil
        ) == SQLITE_OK, let db else {
            throw CausalGraphStoreError.databaseOpenFailed("test raw connection")
        }
        defer { sqlite3_close(db) }
        var errmsg: UnsafeMutablePointer<CChar>?
        let rc = sqlite3_exec(db, sql, nil, nil, &errmsg)
        guard rc == SQLITE_OK else {
            let message = errmsg.map { String(cString: $0) } ?? "unknown"
            sqlite3_free(errmsg)
            throw CausalGraphStoreError.stepFailed("test raw exec: \(message)")
        }
    }

    private static func schemaObjectExists(
        path: String,
        type: String,
        name: String
    ) throws -> Bool {
        var db: OpaquePointer?
        guard sqlite3_open_v2(
            path, &db, SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX, nil
        ) == SQLITE_OK, let db else {
            throw CausalGraphStoreError.databaseOpenFailed("test schema connection")
        }
        defer { sqlite3_close(db) }
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(
            db,
            "SELECT 1 FROM sqlite_master WHERE type = ?1 AND name = ?2 LIMIT 1",
            -1,
            &stmt,
            nil
        ) == SQLITE_OK else {
            throw CausalGraphStoreError.prepareFailed("test schema query")
        }
        defer { sqlite3_finalize(stmt) }
        sqlite3_bind_text(stmt, 1, type, -1, SQLITE_TRANSIENT_TEST)
        sqlite3_bind_text(stmt, 2, name, -1, SQLITE_TRANSIENT_TEST)
        return sqlite3_step(stmt) == SQLITE_ROW
    }

    private static func entity(
        _ id: String,
        payloadBytes: Int = 0,
        at date: Date = Date(timeIntervalSince1970: 1_700_000_000)
    ) -> TraceEntity {
        TraceEntity(
            id: id,
            entityType: "process",
            stableKey: id,
            displayName: id,
            firstSeen: date,
            lastSeen: date,
            attributesJson: "{\"payload\":\"\(String(repeating: "x", count: payloadBytes))\"}",
            source: "storage-admission-test"
        )
    }

    private static func edge(_ id: String, from: String, to: String) -> TraceEdge {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        return TraceEdge(
            id: id,
            sourceEntityId: from,
            targetEntityId: to,
            relation: "spawned",
            firstSeen: now,
            lastSeen: now,
            confidence: 1,
            confidenceTier: "direct",
            evidenceJson: "{}",
            eventIdsJson: "[]"
        )
    }

    private static func trace(
        _ id: String,
        updatedAt: Date? = nil,
        policyPayloadBytes: Int = 0
    ) -> Trace {
        let created = Date(timeIntervalSince1970: 1_700_000_000)
        return Trace(
            id: id,
            title: "Storage admission test",
            anchorEventId: "event-\(id)",
            rootEntityId: "anchor",
            severity: "high",
            confidence: 1,
            createdAt: created,
            updatedAt: updatedAt ?? created,
            daemonVersion: "test",
            rulesetVersion: "test",
            policyId: "default",
            policyVersion: "1",
            policySha256: "test",
            policySnapshotJson: "{\"payload\":\"\(String(repeating: "x", count: policyPayloadBytes))\"}",
            traceSigningKeyMode: "filesystem_degraded",
            replayScope: "declared_deterministic_subset",
            attributionOverridePolicy: "include_as_human_annotation_do_not_apply_by_default"
        )
    }

    @Test("Exact footprint sums main DB, WAL, SHM, and rollback-journal bytes")
    func exactFootprintIncludesAllSQLiteFiles() throws {
        let path = Self.tempPath("sum")
        defer { Self.cleanup(path) }
        try Data(repeating: 1, count: 11).write(to: URL(fileURLWithPath: path))
        try Data(repeating: 2, count: 13).write(to: URL(fileURLWithPath: path + "-wal"))
        try Data(repeating: 3, count: 17).write(to: URL(fileURLWithPath: path + "-shm"))
        try Data(repeating: 4, count: 19).write(to: URL(fileURLWithPath: path + "-journal"))
        #expect(SQLiteCausalGraphStore.exactSQLiteFootprintBytes(databasePath: path) == 60)
    }

    @Test("Unconfigured stores remain compatible even when injected probes fail")
    func unconfiguredStoreDoesNotFailClosed() async throws {
        let path = Self.tempPath("unconfigured")
        defer { Self.cleanup(path) }
        let store = try await SQLiteCausalGraphStore(
            databasePath: path,
            footprintProbe: { _ in nil },
            freeSpaceProbe: { _ in nil }
        )
        try await store.upsertEntity(Self.entity("allowed"))
        #expect(try await store.entity(id: "allowed") != nil)
        #expect(await store.storageAdmissionStatus().enabled == false)
        await store.close()
    }

    @Test("Configured footprint probe failure is fail-closed")
    func footprintProbeFailureFailsClosed() async throws {
        let path = Self.tempPath("footprint-probe")
        defer { Self.cleanup(path) }
        let bootstrap = try await SQLiteCausalGraphStore(databasePath: path)
        await bootstrap.close()
        let store = try await SQLiteCausalGraphStore(
            databasePath: path,
            maxFootprintBytes: 16 * Self.mib,
            transactionReserveBytes: 4 * Self.mib,
            footprintProbe: { _ in nil }
        )
        await #expect(throws: CausalGraphStorageAdmissionError.self) {
            try await store.upsertEntity(Self.entity("denied"))
        }
        #expect(try await store.entity(id: "denied") == nil)
        let status = await store.storageAdmissionStatus()
        #expect(status.blocked)
        #expect(status.reason == .probeFailure)
        #expect(status.shedMutationsTotal == 1)
        await store.close()
    }

    @Test("Configured low-free-space probe blocks before SQLite mutation")
    func lowFreeSpaceFailsClosed() async throws {
        let path = Self.tempPath("low-free")
        defer { Self.cleanup(path) }
        let bootstrap = try await SQLiteCausalGraphStore(databasePath: path)
        await bootstrap.close()
        let store = try await SQLiteCausalGraphStore(
            databasePath: path,
            freeSpaceFloorBytes: 1_000,
            freeSpaceProbe: { _ in 999 }
        )
        await #expect(throws: CausalGraphStorageAdmissionError.self) {
            try await store.upsertEntity(Self.entity("denied"))
        }
        #expect(try await store.entity(id: "denied") == nil)
        let status = await store.storageAdmissionStatus()
        #expect(status.reason == .lowFreeSpace)
        #expect(status.freeSpaceBytes == 999)
        await store.close()
    }

    @Test("Free-space admission preserves the hard floor plus transaction headroom")
    func freeSpaceFloorIncludesMutationHeadroom() async throws {
        let path = Self.tempPath("floor-headroom")
        defer { Self.cleanup(path) }
        let bootstrap = try await SQLiteCausalGraphStore(databasePath: path)
        await bootstrap.close()
        let floor = 10 * Self.mib
        let freeSpace = ProbeBox(floor + Self.mib)
        let store = try await SQLiteCausalGraphStore(
            databasePath: path,
            freeSpaceFloorBytes: floor,
            freeSpaceProbe: { _ in freeSpace.get() }
        )
        // Current free space is above the advertised floor, but this write's
        // conservative upper bound is >1 MiB, so admitting it could cross it.
        await #expect(throws: CausalGraphStorageAdmissionError.self) {
            try await store.upsertEntity(Self.entity("floor-crossing"))
        }
        #expect(try await store.entity(id: "floor-crossing") == nil)
        let blocked = await store.storageAdmissionStatus()
        #expect(blocked.blocked)
        #expect(blocked.reason == .lowFreeSpace)
        #expect(blocked.shedMutationsTotal == 1)

        // Repeated telemetry refreshes retain the stable floor+reserve block
        // without counting another shed mutation or reporting a false recovery.
        let refreshed = await store.storageAdmissionStatus()
        #expect(refreshed.blocked)
        #expect(refreshed.reason == .lowFreeSpace)
        #expect(refreshed.shedMutationsTotal == 1)

        freeSpace.set(floor + 8 * Self.mib)
        // This handle opened while schema writes were unsafe, so it also keeps
        // the idempotent migration/shape-verification gate closed. The first
        // physically admissible growth call completes that deferred work and
        // re-measures before mutating.
        #expect((await store.storageAdmissionStatus()).blocked)
        try await store.upsertEntity(Self.entity("after-headroom"))
        #expect(try await store.entity(id: "after-headroom") != nil)
        #expect(!(await store.storageAdmissionStatus()).blocked)
        await store.close()
    }

    @Test("Runtime cap lowering latches immediately and raising resumes")
    func runtimeLowerAndRaise() async throws {
        let path = Self.tempPath("reload")
        defer { Self.cleanup(path) }
        let footprint = ProbeBox(5 * Self.mib)
        let store = try await SQLiteCausalGraphStore(
            databasePath: path,
            maxFootprintBytes: 10 * Self.mib,
            transactionReserveBytes: 2 * Self.mib,
            footprintProbe: { _ in footprint.get() }
        )
        try await store.upsertEntity(Self.entity("before-lower"))

        let lowered = await store.updateStorageAdmission(
            maxFootprintBytes: 6 * Self.mib,
            freeSpaceFloorBytes: nil,
            transactionReserveBytes: 2 * Self.mib
        )
        #expect(lowered.blocked)
        #expect(lowered.reason == .footprintLimit)
        await #expect(throws: CausalGraphStorageAdmissionError.self) {
            try await store.upsertEntity(Self.entity("while-lowered"))
        }

        let raised = await store.updateStorageAdmission(
            maxFootprintBytes: 12 * Self.mib,
            freeSpaceFloorBytes: nil,
            transactionReserveBytes: 2 * Self.mib
        )
        #expect(!raised.blocked)
        try await store.upsertEntity(Self.entity("after-raise"))
        #expect(try await store.entity(id: "after-raise") != nil)
        await store.close()
    }

    @Test("Recovery target reserves durable transaction headroom")
    func recoveryTargetReservesDurableTransactionHeadroom() async throws {
        let path = Self.tempPath("recovery-hysteresis")
        defer { Self.cleanup(path) }
        let footprint = ProbeBox(0)
        let cap = 250 * Self.mib
        let store = try await SQLiteCausalGraphStore(
            databasePath: path,
            maxFootprintBytes: cap,
            footprintProbe: { _ in footprint.get() }
        )

        let initial = await store.storageAdmissionStatus()
        #expect(initial.transactionReserveBytes == 65_536_000,
                "the shipped transaction reserve must not shrink to create hysteresis")
        let threshold = try #require(initial.admissionThresholdBytes)
        let resume = try #require(initial.resumeBelowBytes)
        #expect(threshold == 196_608_000)
        #expect(resume == threshold - 65_536_000,
                "recovery must leave one complete transaction reserve of headroom")
        #expect(initial.proactiveRecoveryThresholdBytes
            == threshold - (65_536_000 / 4))

        footprint.set(threshold + 1)
        let latched = await store.storageAdmissionStatus()
        #expect(latched.blocked)
        #expect(latched.footprintLatchTripsTotal == 1)
        #expect(latched.recoveryDeficitBytes == 65_536_002)

        let measured = try await store.recoverStorageBudget(
            retentionCutoff: .distantPast,
            orphanCutoff: .distantPast,
            maxTraceDeletes: 0,
            maxTraceChildRows: 0,
            maxGraphDeletesPerTable: 0,
            maxVacuumPages: 0
        )
        #expect(measured.recoveryTargetBytes == resume)
        #expect(measured.recoveryDeficitBytes == 65_536_002)
        #expect(measured.eligibleBacklogRemaining == false)

        footprint.set(resume)
        let boundary = await store.storageAdmissionStatus()
        #expect(boundary.blocked,
                "the latch clears only after crossing below the resume watermark")
        #expect(boundary.footprintLatchClearsTotal == 0)
        #expect(boundary.recoveryDeficitBytes == 1)

        footprint.set(resume - 1)
        let cleared = await store.storageAdmissionStatus()
        #expect(!cleared.blocked)
        #expect(cleared.footprintLatchTripsTotal == 1)
        #expect(cleared.footprintLatchClearsTotal == 1)
        #expect(cleared.recoveryDeficitBytes == 0)

        let reloaded = await store.updateStorageAdmission(
            maxFootprintBytes: cap,
            freeSpaceFloorBytes: nil,
            transactionReserveBytes: nil
        )
        #expect(reloaded.transactionReserveBytes == initial.transactionReserveBytes)
        #expect(reloaded.admissionThresholdBytes == threshold)
        #expect(reloaded.resumeBelowBytes == resume,
                "startup and live-reload policy must derive the same watermark")
        await store.close()
    }

    @Test("Direct and rolling-graph bypass writers all share the SQLite gate")
    func mutationBypassesAreGated() async throws {
        let path = Self.tempPath("bypasses")
        defer { Self.cleanup(path) }
        let footprint = ProbeBox(1 * Self.mib)
        let store = try await SQLiteCausalGraphStore(
            databasePath: path,
            maxFootprintBytes: 64 * Self.mib,
            transactionReserveBytes: 16 * Self.mib,
            footprintProbe: { _ in footprint.get() }
        )
        try await store.upsertBatch(
            entities: [Self.entity("anchor"), Self.entity("target")],
            edges: [Self.edge("seed-edge", from: "anchor", to: "target")]
        )
        try await store.saveTrace(Self.trace("seed"), members: [])
        footprint.set(60 * Self.mib) // above the 48 MiB admission threshold

        await #expect(throws: CausalGraphStorageAdmissionError.self) {
            try await store.upsertEntity(Self.entity("direct-entity"))
        }
        await #expect(throws: CausalGraphStorageAdmissionError.self) {
            try await store.upsertEdge(Self.edge("direct-edge", from: "anchor", to: "target"))
        }
        await #expect(throws: CausalGraphStorageAdmissionError.self) {
            try await store.upsertBatch(entities: [Self.entity("batch")], edges: [])
        }
        await #expect(throws: CausalGraphStorageAdmissionError.self) {
            try await store.saveTrace(Self.trace("blocked-trace"), members: [])
        }
        await #expect(throws: CausalGraphStorageAdmissionError.self) {
            try await store.updateTraceStatus(id: "seed", status: "closed", updatedAt: Date())
        }
        await #expect(throws: CausalGraphStorageAdmissionError.self) {
            try await store.recordRuleHit(TraceRuleHit(
                id: "hit", traceId: "seed", ruleId: "rule", ruleTitle: "rule",
                ruleVersion: "1", severity: "high", matchedAt: Date(), explanationJson: "{}"
            ))
        }
        await #expect(throws: CausalGraphStorageAdmissionError.self) {
            try await store.recordReplayRun(TraceReplayRun(
                id: "replay", traceId: "seed", bundleId: "bundle",
                rulesetVersion: "1", daemonVersion: "1", normalizationVersion: "1",
                startedAt: Date(), completedAt: nil, deterministic: true, resultJson: "{}"
            ))
        }
        await #expect(throws: CausalGraphStorageAdmissionError.self) {
            try await store.appendHashChain(TraceHashChainEntry(
                id: "chain", traceId: "seed", sequenceNumber: 1,
                previousHash: nil, currentHash: "hash"
            ))
        }
        await #expect(throws: CausalGraphStorageAdmissionError.self) {
            _ = try await store.appendTraceContinuity(
                traceId: "seed", eventId: "event", edgeId: nil,
                signature: nil, publishedToUnifiedLog: false
            )
        }
        await #expect(throws: CausalGraphStorageAdmissionError.self) {
            try await store.prefixTraceTitles(ids: ["seed"], with: "[BLOCKED] ")
        }

        let rolling = RollingCausalGraph(
            store: store,
            materializer: TraceMaterializer(store: store)
        )
        await #expect(throws: CausalGraphStorageAdmissionError.self) {
            _ = try await rolling.recordExternalAnchor(
                anchorEntityId: "anchor",
                anchorEventId: "event",
                reason: "blocked external anchor",
                severity: "high",
                confidence: 1,
                observedAt: Date(timeIntervalSince1970: 1_700_000_000)
            )
        }
        #expect(await store.storageAdmissionStatus().shedMutationsTotal == 11)
        await store.close()
    }

    @Test("Every admitted transaction leaves the SQLite family at or below the exact cap")
    func exactCapCannotBeOvershotByAdmittedTransaction() async throws {
        let path = Self.tempPath("exact-cap")
        defer { Self.cleanup(path) }
        let cap = 12 * Self.mib
        let store = try await SQLiteCausalGraphStore(
            databasePath: path,
            maxFootprintBytes: cap,
            transactionReserveBytes: 2 * Self.mib
        )

        var admissionStopped = false
        for i in 0..<2_000 {
            do {
                try await store.upsertEntity(Self.entity("large-\(i)", payloadBytes: 16_384))
                let footprint = try #require(await store.storageFootprintBytes())
                #expect(footprint <= cap,
                        "an admitted transaction overshot cap: \(footprint) > \(cap)")
            } catch is CausalGraphStorageAdmissionError {
                admissionStopped = true
                break
            }
        }
        #expect(admissionStopped, "fixture never reached the admission threshold")
        #expect(try #require(await store.storageFootprintBytes()) <= cap)
        #expect(await store.storageAdmissionStatus().reason == .footprintLimit)
        await store.close()
    }

    @Test("SQLite max_page_count FULL is translated into a latched admission error")
    func sqliteFullBackstopIsTypedAndLatched() async throws {
        let path = Self.tempPath("sqlite-full")
        defer { Self.cleanup(path) }
        let reportedFootprint = ProbeBox(0)
        let store = try await SQLiteCausalGraphStore(
            databasePath: path,
            footprintProbe: { _ in reportedFootprint.get() }
        )
        for index in 0..<100 {
            try await store.upsertEntity(Self.entity("seed-\(index)", payloadBytes: 512))
        }
        #expect(await store.walCheckpointTruncate())
        let pages = try Self.pragmaInt64(path: path, name: "page_count")
        let pageSize = try Self.pragmaInt64(path: path, name: "page_size")
        let threshold = pages * pageSize
        _ = await store.updateStorageAdmission(
            maxFootprintBytes: threshold + 2 * Self.mib,
            freeSpaceFloorBytes: nil,
            transactionReserveBytes: 2 * Self.mib
        )

        var caughtTyped = false
        for index in 0..<5_000 {
            do {
                try await store.upsertEntity(
                    Self.entity("backstop-\(index)", payloadBytes: 4_096))
            } catch is CausalGraphStorageAdmissionError {
                caughtTyped = true
                break
            } catch {
                Issue.record("SQLite FULL escaped as generic error: \(error)")
                break
            }
        }
        #expect(caughtTyped, "fixture never reached max_page_count")
        reportedFootprint.set(threshold + 1)
        let firstStatus = await store.storageAdmissionStatus()
        #expect(firstStatus.reason == .footprintLimit)
        let shedsBefore = firstStatus.shedMutationsTotal
        await #expect(throws: CausalGraphStorageAdmissionError.self) {
            try await store.upsertEntity(Self.entity("still-latched"))
        }
        #expect(await store.storageAdmissionStatus().shedMutationsTotal == shedsBefore + 1)
        await store.close()
    }

    @Test("Configured live stores refuse full VACUUM and bound incremental work")
    func configuredMaintenanceIsBounded() async throws {
        let path = Self.tempPath("configured-maintenance")
        defer { Self.cleanup(path) }
        let store = try await SQLiteCausalGraphStore(
            databasePath: path,
            maxFootprintBytes: 64 * Self.mib,
            transactionReserveBytes: 8 * Self.mib
        )
        await #expect(throws: CausalGraphStoreError.self) {
            try await store.vacuum()
        }
        // A hostile/unbounded request is reduced to one reserve-sized quantum.
        _ = try await store.incrementalVacuum(maxPages: Int.max)
        try await store.upsertEntity(Self.entity("still-open"))
        #expect(try await store.entity(id: "still-open") != nil)
        await store.close()
    }

    @Test("Every TraceGraph checkpoint preserves floor plus allocated sidecars")
    func checkpointHeadroomUsesFreshSidecarBytes() async throws {
        let path = Self.tempPath("checkpoint-headroom")
        defer { Self.cleanup(path) }
        let bootstrap = try await SQLiteCausalGraphStore(databasePath: path)
        await bootstrap.close()

        let footprint = ProbeBox(
            SQLiteCausalGraphStore.exactSQLiteFootprintBytes(
                databasePath: path
            )
        )
        let free = ProbeBox(Int64.max)
        let floor: Int64 = 10_000
        let store = try await SQLiteCausalGraphStore(
            databasePath: path,
            freeSpaceFloorBytes: floor,
            footprintProbe: { _ in footprint.get() },
            freeSpaceProbe: { _ in free.get() }
        )

        let sidecars: Int64 = 4_096
        let main = try SQLitePersistentStoreAdmission.measureMainFile(path)
        footprint.set(main + sidecars)
        free.set(floor + sidecars)
        #expect(await store.walCheckpoint(),
                "the exact floor+sidecar boundary must be admitted")

        let mainAfter = try SQLitePersistentStoreAdmission.measureMainFile(path)
        footprint.set(mainAfter + sidecars)
        free.set(floor + sidecars - 1)
        #expect(!(await store.walCheckpointTruncate()),
                "checkpoint must not consume one byte below the hard floor")
        let blocked = await store.storageAdmissionStatus()
        #expect(blocked.reason == .lowFreeSpace)
        #expect(blocked.freeSpaceBytes == floor + sidecars - 1)
        #expect(blocked.shedMutationsTotal == 0,
                "deferring maintenance is not a shed graph mutation")
        await store.close()
    }

    @Test("Reader-pinned WAL prevents every recovery delete until reader releases")
    func pinnedReaderRecoveryDoesNotDelete() async throws {
        let path = Self.tempPath("pinned-reader")
        defer { Self.cleanup(path) }
        let store = try await SQLiteCausalGraphStore(databasePath: path)
        try await store.upsertEntity(Self.entity("anchor"))
        try await store.saveTrace(Self.trace("expired"), members: [])

        var reader: OpaquePointer?
        #expect(sqlite3_open_v2(
            path, &reader, SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX, nil
        ) == SQLITE_OK)
        defer { if let reader { sqlite3_close(reader) } }
        let openedReader = try #require(reader)
        #expect(sqlite3_exec(openedReader, "BEGIN", nil, nil, nil) == SQLITE_OK)
        var stmt: OpaquePointer?
        #expect(sqlite3_prepare_v2(
            openedReader, "SELECT COUNT(*) FROM traces", -1, &stmt, nil
        ) == SQLITE_OK)
        #expect(sqlite3_step(stmt) == SQLITE_ROW)
        sqlite3_finalize(stmt)

        // Add a frame after the reader's end mark so PASSIVE/TRUNCATE reports
        // the actual frame gap even though the WAL is far below 64 MiB.
        try await store.upsertEntity(Self.entity("after-reader"))
        let pinned = try await store.recoverStorageBudget(
            retentionCutoff: Date(),
            orphanCutoff: .distantPast,
            maxTraceDeletes: 1,
            maxGraphDeletesPerTable: 0,
            maxVacuumPages: 0
        )
        #expect(pinned.pinnedReader)
        #expect(pinned.tracesDeleted == 0)
        #expect(try await store.loadTrace(id: "expired") != nil)

        #expect(sqlite3_exec(openedReader, "COMMIT", nil, nil, nil) == SQLITE_OK)
        sqlite3_close(openedReader)
        reader = nil

        let recovered = try await store.recoverStorageBudget(
            retentionCutoff: Date(),
            orphanCutoff: .distantPast,
            maxTraceDeletes: 1,
            maxGraphDeletesPerTable: 0,
            maxVacuumPages: 0
        )
        #expect(!recovered.pinnedReader)
        #expect(recovered.tracesDeleted == 1)
        #expect(try await store.loadTrace(id: "expired") == nil)
        await store.close()
    }

    @Test("Startup grants a bounded reader grace period and then fails pinned readers closed")
    func startupPinnedReaderGraceIsBoundedAndNonDestructive() async throws {
        func makePinned(
            _ label: String
        ) async throws -> (SQLiteCausalGraphStore, String, ProbeBox, ReaderLease) {
            let path = Self.tempPath(label)
            let footprint = ProbeBox(Self.mib)
            let store = try await SQLiteCausalGraphStore(
                databasePath: path,
                maxFootprintBytes: 64 * Self.mib,
                transactionReserveBytes: 8 * Self.mib,
                footprintProbe: { _ in footprint.get() }
            )
            try await store.saveTrace(
                Self.trace("old-\(label)", updatedAt: .distantPast),
                members: []
            )
            #expect(await store.walCheckpointTruncate())
            let reader = try ReaderLease(path: path)
            try await store.upsertEntity(Self.entity("after-reader-\(label)"))
            footprint.set(60 * Self.mib)
            _ = await store.updateStorageAdmission(
                maxFootprintBytes: 64 * Self.mib,
                freeSpaceFloorBytes: nil,
                transactionReserveBytes: 8 * Self.mib
            )
            return (store, path, footprint, reader)
        }

        let (transient, transientPath, transientFootprint, transientReader) =
            try await makePinned("startup-transient-pin")
        defer { Self.cleanup(transientPath) }
        let release = Task {
            try? await Task.sleep(for: .milliseconds(60))
            transientFootprint.set(Self.mib)
            transientReader.release()
        }
        let recovered = await transient.recoverStorageBeforeProducers(
            configuredRetentionHours: 7 * 24,
            cutoffRungs: [72, 24, 6, 1],
            maximumPasses: 12
        )
        _ = await release.result
        #expect(recovered.writableBeforeProducers)
        #expect(recovered.passes >= 1,
                "the pin may clear inside SQLite's bounded busy wait or on a retry")
        #expect(recovered.lastRecovery?.tracesDeleted == 0,
                "a clearing reader pin must not force evidence deletion")
        await transient.close()

        let (permanent, permanentPath, _, permanentReader) =
            try await makePinned("startup-permanent-pin")
        defer {
            permanentReader.release()
            Self.cleanup(permanentPath)
        }
        let blocked = await permanent.recoverStorageBeforeProducers(
            configuredRetentionHours: 7 * 24,
            cutoffRungs: [72, 24, 6, 1],
            maximumPasses: 12
        )
        #expect(blocked.disposition == .nonconverged(.pinnedReader))
        #expect(blocked.passes == 8)
        #expect(blocked.lastRecovery?.tracesDeleted == 0)
        #expect(try await permanent.loadTrace(
            id: "old-startup-permanent-pin") != nil)
        await permanent.close()
    }

    @Test("Pressured legacy mode-0 store preserves evidence for offline conversion")
    func pressuredLegacyStoreDoesNotDeleteWithoutPhysicalReclaim() async throws {
        let path = Self.tempPath("legacy-mode-zero-pressure")
        defer { Self.cleanup(path) }

        // Create a non-empty mode-0 file before the store's schema exists.
        // SQLite cannot make the later auto_vacuum pragma effective without a
        // full VACUUM, reproducing an inherited pre-Wave-9B database.
        var raw: OpaquePointer?
        #expect(sqlite3_open_v2(
            path, &raw,
            SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
            nil
        ) == SQLITE_OK)
        let rawDB = try #require(raw)
        #expect(sqlite3_exec(
            rawDB,
            "PRAGMA auto_vacuum = NONE; CREATE TABLE legacy_seed(value TEXT); INSERT INTO legacy_seed VALUES ('seed');",
            nil, nil, nil
        ) == SQLITE_OK)
        sqlite3_close(rawDB)
        raw = nil

        let bootstrap = try await SQLiteCausalGraphStore(databasePath: path)
        #expect(await bootstrap.autoVacuumMode() == 0,
                "fixture must remain an inherited mode-0 database")
        try await bootstrap.saveTrace(
            Self.trace("preserve-me", updatedAt: .distantPast), members: [])
        await bootstrap.close()

        let reportedFootprint = ProbeBox(13 * Self.mib)
        let store = try await SQLiteCausalGraphStore(
            databasePath: path,
            maxFootprintBytes: 16 * Self.mib,
            transactionReserveBytes: 4 * Self.mib,
            footprintProbe: { _ in reportedFootprint.get() }
        )
        let before = await store.storageAdmissionStatus()
        #expect(before.blocked)
        #expect(before.reason == .footprintLimit)

        let recovery = try await store.recoverStorageBudget(
            retentionCutoff: Date(),
            orphanCutoff: Date(),
            maxTraceDeletes: 1,
            maxGraphDeletesPerTable: 1,
            maxVacuumPages: 8_192
        )
        #expect(recovery.autoVacuumMode == 0)
        #expect(recovery.tracesDeleted == 0)
        #expect(recovery.edgesDeleted == 0)
        #expect(recovery.entitiesDeleted == 0)
        #expect(recovery.vacuumPagesReclaimed == 0)
        #expect(try await store.loadTrace(id: "preserve-me") != nil,
                "mode-0 DELETE cannot reclaim the file and must not destroy evidence")
        #expect((await store.storageAdmissionStatus()).blocked,
                "physical pressure remains until the offline conversion")
        await store.close()
    }

    @Test("High-fanout trace pruning stays inside the reserved cap window")
    func tracePruningUsesSmallCheckpointedTransactions() async throws {
        let path = Self.tempPath("cascade-batches")
        defer { Self.cleanup(path) }
        let store = try await SQLiteCausalGraphStore(databasePath: path)
        let traceTotal = 24
        let membershipsPerTrace = 350 // close to field-observed ~332/trace

        for traceIndex in 0..<traceTotal {
            let id = "fanout-\(traceIndex)"
            let members = (0..<membershipsPerTrace).map { memberIndex in
                TraceMembership(
                    traceId: id,
                    entityId: "entity-\(traceIndex)-\(memberIndex)",
                    role: "context",
                    layer: "context"
                )
            }
            try await store.saveTrace(
                Self.trace(id, updatedAt: Date(timeIntervalSince1970: Double(traceIndex))),
                members: members
            )
        }
        #expect(await store.walCheckpointTruncate())
        let before = try #require(await store.storageFootprintBytes())
        let reserve = 16 * Self.mib
        let cap = before + reserve + Self.mib
        let status = await store.updateStorageAdmission(
            maxFootprintBytes: cap,
            freeSpaceFloorBytes: nil,
            transactionReserveBytes: reserve
        )
        #expect(!status.blocked)

        let monitor = FootprintMonitor()
        monitor.record(before)
        let sampler = Task.detached(priority: .high) {
            while true {
                let state = monitor.snapshot()
                if state.finished { return state.maximum }
                if let value = SQLiteCausalGraphStore.exactSQLiteFootprintBytes(
                    databasePath: path) {
                    monitor.record(value)
                }
                try? await Task.sleep(nanoseconds: 250_000)
            }
        }
        let deleted = try await store.pruneOldestTraces(count: traceTotal)
        monitor.finish()
        let observedMaximum = await sampler.value

        #expect(deleted == traceTotal)
        #expect(try await store.traceCount() == 0)
        #expect(observedMaximum <= cap,
                "checkpointed cascade exceeded reserve: \(observedMaximum) > \(cap)")
        #expect(try #require(await store.storageFootprintBytes()) <= cap)
        await store.close()
    }

    @Test("One recovery tick bounds a pathological trace's child-row fanout")
    func recoveryBoundsChildRowsAcrossTicks() async throws {
        let path = Self.tempPath("pathological-fanout")
        defer { Self.cleanup(path) }
        let store = try await SQLiteCausalGraphStore(databasePath: path)
        let traceID = "pathological"
        let members = (0..<1_000).map { index in
            TraceMembership(
                traceId: traceID,
                entityId: "member-\(index)",
                role: "context",
                layer: "context"
            )
        }
        try await store.saveTrace(
            Self.trace(traceID, updatedAt: .distantPast), members: members)
        #expect(try await store.memberCount(traceId: traceID) == 1_000)

        let first = try await store.recoverStorageBudget(
            retentionCutoff: Date(),
            orphanCutoff: .distantPast,
            maxTraceDeletes: 1,
            maxTraceChildRows: 100,
            maxGraphDeletesPerTable: 0,
            maxVacuumPages: 0
        )
        #expect(first.tracesDeleted == 0)
        #expect(try await store.memberCount(traceId: traceID) == 900)
        #expect(try await store.loadTrace(id: traceID) != nil)

        var previousCount = 900
        var deleted = 0
        for _ in 0..<9 {
            let pass = try await store.recoverStorageBudget(
                retentionCutoff: Date(),
                orphanCutoff: .distantPast,
                maxTraceDeletes: 1,
                maxTraceChildRows: 100,
                maxGraphDeletesPerTable: 0,
                maxVacuumPages: 0
            )
            deleted += pass.tracesDeleted
            let count = try await store.memberCount(traceId: traceID)
            #expect(previousCount - count <= 100)
            previousCount = count
        }
        #expect(deleted == 1)
        #expect(try await store.loadTrace(id: traceID) == nil)
        await store.close()
    }

    @Test("Writable ancestor redirection is rejected before SQLite open")
    func unsafeAncestorSymlinkTargetIsRejected() async throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("tracegraph-ancestor-\(UUID().uuidString)")
        let target = root.appendingPathComponent("world-writable")
        let link = root.appendingPathComponent("redirect")
        defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createDirectory(
            at: target, withIntermediateDirectories: true)
        #expect(chmod(target.path, 0o777) == 0)
        try FileManager.default.createSymbolicLink(
            at: link, withDestinationURL: target)

        await #expect(throws: CausalGraphStoreError.self) {
            _ = try await SQLiteCausalGraphStore(
                databasePath: link.appendingPathComponent("tracegraph.db").path)
        }
        #expect(!FileManager.default.fileExists(
            atPath: target.appendingPathComponent("tracegraph.db").path))
    }

    @Test("Root sticky ancestors are rejected even when the leaf is regular")
    func stickyAncestorIsRejected() async throws {
        let path = "/private/tmp/tracegraph-sticky-\(UUID().uuidString).db"
        defer { Self.cleanup(path) }
        #expect(FileManager.default.createFile(
            atPath: path, contents: Data("attacker-controlled".utf8)))
        #expect(chmod(path, 0o600) == 0)

        await #expect(throws: CausalGraphStoreError.self) {
            _ = try await SQLiteCausalGraphStore(databasePath: path)
        }
    }

    @Test("A planted SQLite leaf symlink is rejected without touching its target")
    func attackerControlledLeafSymlinkIsRejected() async throws {
        let leaf = Self.tempPath("attacker-leaf")
        let target = Self.tempPath("attacker-target")
        defer {
            Self.cleanup(leaf)
            Self.cleanup(target)
        }
        let sentinel = Data("must-not-change".utf8)
        #expect(FileManager.default.createFile(atPath: target, contents: sentinel))
        try FileManager.default.createSymbolicLink(
            atPath: leaf, withDestinationPath: target)

        await #expect(throws: CausalGraphStoreError.self) {
            _ = try await SQLiteCausalGraphStore(databasePath: leaf)
        }
        #expect(try Data(contentsOf: URL(fileURLWithPath: target)) == sentinel)
    }

    @Test("Unsafe main and sidecar modes are rejected through descriptor validation")
    func unsafeSQLiteFamilyModesAreRejected() async throws {
        let unsafeMain = Self.tempPath("unsafe-main-mode")
        defer { Self.cleanup(unsafeMain) }
        #expect(FileManager.default.createFile(atPath: unsafeMain, contents: Data()))
        #expect(chmod(unsafeMain, 0o666) == 0)
        await #expect(throws: CausalGraphStoreError.self) {
            _ = try await SQLiteCausalGraphStore(databasePath: unsafeMain)
        }

        let unsafeSidecar = Self.tempPath("unsafe-sidecar-mode")
        defer { Self.cleanup(unsafeSidecar) }
        let seed = try await SQLiteCausalGraphStore(databasePath: unsafeSidecar)
        await seed.close()
        #expect(FileManager.default.createFile(
            atPath: unsafeSidecar + "-wal", contents: Data()))
        #expect(chmod(unsafeSidecar + "-wal", 0o666) == 0)
        await #expect(throws: CausalGraphStoreError.self) {
            _ = try await SQLiteCausalGraphStore(databasePath: unsafeSidecar)
        }
    }

    @Test("Trace reclaim is measured before pressure fallback crosses into graph evidence")
    func traceReclaimPreventsGraphFallbackOverDeletion() async throws {
        let path = Self.tempPath("trace-before-graph")
        defer { Self.cleanup(path) }
        let store = try await SQLiteCausalGraphStore(databasePath: path)

        try await store.upsertBatch(
            entities: [Self.entity("graph-a"), Self.entity("graph-b")],
            edges: [Self.edge("graph-edge", from: "graph-a", to: "graph-b")]
        )
        let traceID = "large-expired-trace"
        let oldEvidence = Date(timeIntervalSince1970: 1_600_000_000)
        try await store.saveTrace(
            Self.trace(traceID, updatedAt: oldEvidence), members: [])
        let payload = "{\"payload\":\"\(String(repeating: "x", count: 24 * 1_024))\"}"
        for index in 0..<96 {
            try await store.recordRuleHit(TraceRuleHit(
                id: "hit-\(index)", traceId: traceID,
                ruleId: "rule", ruleTitle: "rule", ruleVersion: "1",
                severity: "high", matchedAt: oldEvidence,
                explanationJson: payload
            ))
        }
        #expect(await store.walCheckpointTruncate())
        let before = try #require(await store.storageFootprintBytes())
        let reserve = 8 * Self.mib
        let status = await store.updateStorageAdmission(
            maxFootprintBytes: before + reserve - (Self.mib / 2),
            freeSpaceFloorBytes: nil,
            transactionReserveBytes: reserve
        )
        #expect(status.blocked)

        let recovery = try await store.recoverStorageBudget(
            retentionCutoff: Date(),
            orphanCutoff: Date(),
            maxTraceDeletes: 1,
            maxTraceChildRows: 16_384,
            maxGraphDeletesPerTable: 10,
            maxVacuumPages: 8_192
        )
        #expect(recovery.tracesDeleted == 1)
        #expect(recovery.vacuumPagesReclaimed > 0)
        #expect(try await store.loadTrace(id: traceID) == nil)
        #expect(try await store.edge(id: "graph-edge") != nil,
                "graph pressure fallback ran despite trace reclaim satisfying the cap")
        #expect(try await store.entity(id: "graph-a") != nil)
        #expect(!(await store.storageAdmissionStatus().blocked))
        await store.close()
    }

    @Test("Pressured mode-FULL recovery remeasures edges before entity fallback")
    func edgeReclaimDoesNotCrossIntoEntityEvidenceInTheSamePass() async throws {
        let path = Self.tempPath("edge-before-entity")
        defer { Self.cleanup(path) }
        let bootstrap = try await SQLiteCausalGraphStore(databasePath: path)
        try await bootstrap.upsertBatch(
            entities: [
                Self.entity("edge-source"), Self.entity("edge-target"),
                Self.entity("independent-orphan"),
            ],
            edges: [Self.edge(
                "eligible-edge", from: "edge-source", to: "edge-target")]
        )
        #expect(await bootstrap.walCheckpointTruncate())
        await bootstrap.close()
        try Self.rawExec(path: path, sql: """
            PRAGMA journal_mode = DELETE;
            PRAGMA auto_vacuum = FULL;
            """)
        #expect(try Self.pragmaInt64(path: path, name: "auto_vacuum") == 1)
        let store = try await SQLiteCausalGraphStore(
            databasePath: path,
            maxFootprintBytes: 64 * Self.mib,
            transactionReserveBytes: 8 * Self.mib,
            footprintProbe: { _ in 60 * Self.mib }
        )
        let recovery = try await store.recoverStorageBudget(
            retentionCutoff: Date(),
            orphanCutoff: Date(),
            maxTraceDeletes: 0,
            maxGraphDeletesPerTable: 8,
            maxVacuumPages: 0
        )
        #expect(recovery.autoVacuumMode == 1)
        #expect(recovery.edgesDeleted == 1)
        #expect(recovery.entitiesDeleted == 0,
                "entity fallback must wait for a fresh post-edge pass")
        #expect(try await store.entity(id: "independent-orphan") != nil)
        await store.close()
    }

    @Test("One inherited oversized child row is preserved for offline repair")
    func oversizedCascadeRowNeverEntersAnUnboundedDelete() async throws {
        let path = Self.tempPath("oversized-cascade-row")
        defer { Self.cleanup(path) }
        let store = try await SQLiteCausalGraphStore(databasePath: path)
        let traceID = "oversized"
        try await store.saveTrace(
            Self.trace(traceID, updatedAt: .distantPast), members: [])
        try await store.recordRuleHit(TraceRuleHit(
            id: "oversized-hit", traceId: traceID,
            ruleId: "rule", ruleTitle: "rule", ruleVersion: "1",
            severity: "high", matchedAt: Date(),
            explanationJson: String(repeating: "x", count: 2 * 1_024 * 1_024)
        ))

        let recovery = try await store.recoverStorageBudget(
            retentionCutoff: Date(),
            orphanCutoff: .distantPast,
            maxTraceDeletes: 1,
            maxTraceChildRows: 100,
            maxGraphDeletesPerTable: 0,
            maxVacuumPages: 0
        )
        #expect(recovery.tracesDeleted == 0)
        #expect(try await store.loadTrace(id: traceID) != nil,
                "parent must remain while its oversized child is preserved")
        await store.close()
    }

    @Test("One inherited oversized parent row is preserved for offline repair")
    func oversizedCascadeParentNeverEntersAnUnboundedDelete() async throws {
        let path = Self.tempPath("oversized-cascade-parent")
        defer { Self.cleanup(path) }
        let store = try await SQLiteCausalGraphStore(databasePath: path)
        let traceID = "oversized-parent"
        try await store.saveTrace(
            Self.trace(
                traceID,
                updatedAt: .distantPast,
                policyPayloadBytes: 2 * 1_024 * 1_024
            ),
            members: []
        )

        let recovery = try await store.recoverStorageBudget(
            retentionCutoff: Date(),
            orphanCutoff: .distantPast,
            maxTraceDeletes: 1,
            maxTraceChildRows: 100,
            maxGraphDeletesPerTable: 0,
            maxVacuumPages: 0
        )
        #expect(recovery.tracesDeleted == 0)
        #expect(try await store.loadTrace(id: traceID) != nil,
                "oversized parent must remain for bounded offline repair")
        await store.close()
    }

    @Test("Recovery skips oversized substrate/trace rows and preserves inverted recent timestamps")
    func recoverySelectionBoundsDoNotStarveSafeCandidates() async throws {
        let path = Self.tempPath("bounded-selection-starvation")
        defer { Self.cleanup(path) }
        let store = try await SQLiteCausalGraphStore(databasePath: path)
        let old = Date(timeIntervalSince1970: 1_600_000_000)
        let recent = Date(timeIntervalSince1970: 2_000_000_000)
        let cutoff = Date(timeIntervalSince1970: 1_900_000_000)

        let stuckTrace = "a-oversized-child"
        try await store.saveTrace(
            Self.trace(stuckTrace, updatedAt: old), members: [])
        try await store.recordRuleHit(TraceRuleHit(
            id: "oversized-child", traceId: stuckTrace,
            ruleId: "rule", ruleTitle: "rule", ruleVersion: "1",
            severity: "high", matchedAt: old,
            explanationJson: String(repeating: "x", count: 2 * 1_048_576)
        ))
        for index in 0..<12 {
            let id = "normal-child-\(index)"
            try await store.saveTrace(Self.trace(id, updatedAt: old), members: [])
            try await store.recordRuleHit(TraceRuleHit(
                id: "normal-hit-\(index)", traceId: id,
                ruleId: "rule", ruleTitle: "rule", ruleVersion: "1",
                severity: "high", matchedAt: old,
                explanationJson: "{}"
            ))
        }

        let oversizedEntity = Self.entity(
            "oversized-entity", payloadBytes: 2 * 1_048_576, at: old)
        let normalEntity = Self.entity("normal-entity", at: old)
        try await store.upsertBatch(
            entities: [oversizedEntity, normalEntity],
            edges: []
        )

        let recovery = try await store.recoverStorageBudget(
            retentionCutoff: cutoff,
            orphanCutoff: cutoff,
            maxTraceDeletes: 64,
            maxTraceChildRows: 1_024,
            maxGraphDeletesPerTable: 64,
            maxVacuumPages: 0
        )
        #expect(recovery.tracesDeleted == 12,
                "one oversized trace child must not starve later trace batches")
        #expect(try await store.loadTrace(id: stuckTrace) != nil)
        #expect(try await store.loadTrace(id: "normal-child-11") == nil)
        #expect(try await store.entity(id: "normal-entity") == nil)
        #expect(try await store.entity(id: "oversized-entity") != nil,
                "a substrate row above the reserve must remain for offline repair")
        #expect(recovery.orphanBacklogRemaining == true,
                "the preserved oversized row remains visible for offline repair")
        await store.close()

        let timestampPath = Self.tempPath("inverted-substrate-time")
        defer { Self.cleanup(timestampPath) }
        let timestampStore = try await SQLiteCausalGraphStore(
            databasePath: timestampPath)
        let invertedEntity = TraceEntity(
            id: "inverted-entity", entityType: "process",
            stableKey: "inverted-entity", displayName: "inverted-entity",
            firstSeen: recent, lastSeen: old, attributesJson: "{}",
            source: "test"
        )
        try await timestampStore.upsertEntity(invertedEntity)
        let timestampRecovery = try await timestampStore.recoverStorageBudget(
            retentionCutoff: cutoff,
            orphanCutoff: cutoff,
            maxTraceDeletes: 0,
            maxGraphDeletesPerTable: 8,
            maxVacuumPages: 0
        )
        #expect(try await timestampStore.entity(id: "inverted-entity") != nil,
                "recent first_seen evidence must dominate an inherited old last_seen")
        #expect(timestampRecovery.orphanBacklogRemaining == false,
                "exact backlog must use the same effective timestamp predicate")
        await timestampStore.close()
    }

    @Test("FULL and IOERR quota metadata latch configured growth admission")
    func sqliteStorageMetadataLatchesAdmission() async throws {
        let path = Self.tempPath("sqlite-failure-latch")
        defer { Self.cleanup(path) }
        let store = try await SQLiteCausalGraphStore(
            databasePath: path,
            maxFootprintBytes: 64 * Self.mib,
            footprintProbe: { _ in Self.mib }
        )
        let failures = [
            SQLiteFailureMetadata(
                resultCode: SQLITE_FULL,
                extendedResultCode: SQLITE_FULL,
                systemErrno: 0
            ),
            SQLiteFailureMetadata(
                resultCode: SQLITE_IOERR,
                extendedResultCode: SQLITE_IOERR | Int32(3 << 8),
                systemErrno: ENOSPC
            ),
            SQLiteFailureMetadata(
                resultCode: SQLITE_IOERR,
                extendedResultCode: SQLITE_IOERR | Int32(4 << 8),
                systemErrno: EDQUOT
            ),
        ]

        for (index, failure) in failures.enumerated() {
            _ = await store.updateStorageAdmission(
                maxFootprintBytes: 64 * Self.mib,
                freeSpaceFloorBytes: nil
            )
            #expect(await store.latchSQLiteStorageFailure(
                failure, context: "injected maintenance failure") != nil)
            #expect(await store.storageAdmissionStatus().reason == .footprintLimit)
            await #expect(throws: CausalGraphStorageAdmissionError.self) {
                try await store.upsertEntity(Self.entity("blocked-\(index)"))
            }
        }
        await store.close()
    }

    @Test("Deferred v1 store completes every index/trigger before growth resumes")
    func deferredMigrationsGateRecoveryResume() async throws {
        let path = Self.tempPath("deferred-migrations")
        defer { Self.cleanup(path) }
        let bootstrap = try await SQLiteCausalGraphStore(databasePath: path)
        await bootstrap.close()
        try Self.rawExec(path: path, sql: """
            DROP TRIGGER trg_hash_chain_global_sequence_unique;
            DROP INDEX idx_hash_chain_global_seq;
            DROP INDEX idx_entities_lastseen;
            DROP INDEX idx_edges_lastseen;
            PRAGMA user_version = 1;
            """)
        #expect(!(try Self.schemaObjectExists(
            path: path, type: "index", name: "idx_hash_chain_global_seq")))

        let footprint = ProbeBox(60 * Self.mib)
        let store = try await SQLiteCausalGraphStore(
            databasePath: path,
            maxFootprintBytes: 64 * Self.mib,
            transactionReserveBytes: 8 * Self.mib,
            footprintProbe: { _ in footprint.get() }
        )
        #expect((await store.storageAdmissionStatus()).blocked)
        #expect(!(try Self.schemaObjectExists(
            path: path, type: "index", name: "idx_hash_chain_global_seq")),
                "over-budget init must defer index growth")

        footprint.set(Self.mib)
        _ = try await store.recoverStorageBudget(
            retentionCutoff: .distantPast,
            orphanCutoff: .distantPast,
            maxTraceDeletes: 0,
            maxTraceChildRows: 0,
            maxGraphDeletesPerTable: 0,
            maxVacuumPages: 0
        )
        #expect(try Self.schemaObjectExists(
            path: path, type: "index", name: "idx_hash_chain_global_seq"))
        #expect(try Self.schemaObjectExists(
            path: path, type: "index", name: "idx_entities_lastseen"))
        #expect(try Self.schemaObjectExists(
            path: path, type: "index", name: "idx_edges_lastseen"))
        #expect(try Self.schemaObjectExists(
            path: path, type: "trigger",
            name: "trg_hash_chain_global_sequence_unique"))
        #expect(!(await store.storageAdmissionStatus()).blocked)
        try await store.upsertEntity(Self.entity("after-deferred-migration"))
        #expect(try await store.entity(id: "after-deferred-migration") != nil)
        await store.close()
    }

    @Test("Malformed deferred migration objects remain fail-closed and visible")
    func malformedDeferredMigrationNeverResumesGrowth() async throws {
        let path = Self.tempPath("bad-deferred-migration")
        defer { Self.cleanup(path) }
        let bootstrap = try await SQLiteCausalGraphStore(databasePath: path)
        await bootstrap.close()
        try Self.rawExec(path: path, sql: """
            DROP TRIGGER trg_hash_chain_global_sequence_unique;
            DROP INDEX idx_hash_chain_global_seq;
            CREATE INDEX idx_hash_chain_global_seq
                ON trace_hash_chain(trace_id);
            PRAGMA user_version = 2;
            """)

        let footprint = ProbeBox(60 * Self.mib)
        let store = try await SQLiteCausalGraphStore(
            databasePath: path,
            maxFootprintBytes: 64 * Self.mib,
            transactionReserveBytes: 8 * Self.mib,
            footprintProbe: { _ in footprint.get() }
        )
        footprint.set(Self.mib)
        await #expect(throws: CausalGraphStoreError.self) {
            _ = try await store.recoverStorageBudget(
                retentionCutoff: .distantPast,
                orphanCutoff: .distantPast,
                maxTraceDeletes: 0,
                maxTraceChildRows: 0,
                maxGraphDeletesPerTable: 0,
                maxVacuumPages: 0
            )
        }
        let status = await store.storageAdmissionStatus()
        #expect(status.blocked)
        #expect(status.reason == .probeFailure)
        await #expect(throws: CausalGraphStorageAdmissionError.self) {
            try await store.upsertEntity(Self.entity("must-stay-blocked"))
        }
        #expect(try await store.entity(id: "must-stay-blocked") == nil)
        await store.close()
    }

    @Test("BEGIN, COMMIT, and ROLLBACK storage faults fail closed atomically")
    func transactionControlFailuresAreChecked() async throws {
        func makeConfiguredStore(
            _ label: String,
            probe: @escaping CausalGraphTransactionFailureProbe
        ) async throws -> (SQLiteCausalGraphStore, String) {
            let path = Self.tempPath(label)
            let bootstrap = try await SQLiteCausalGraphStore(databasePath: path)
            await bootstrap.close()
            let store = try await SQLiteCausalGraphStore(
                databasePath: path,
                maxFootprintBytes: 64 * Self.mib,
                footprintProbe: { _ in Self.mib },
                transactionFailureProbe: probe
            )
            return (store, path)
        }

        let full = CausalGraphInjectedSQLiteFailure(resultCode: SQLITE_FULL)
        let (beginStore, beginPath) = try await makeConfiguredStore(
            "begin-failure",
            probe: { $0 == .begin ? full : nil }
        )
        defer { Self.cleanup(beginPath) }
        await #expect(throws: CausalGraphStorageAdmissionError.self) {
            try await beginStore.upsertBatch(
                entities: [Self.entity("begin-row")], edges: [])
        }
        #expect(try await beginStore.entity(id: "begin-row") == nil)
        await beginStore.close()

        let (commitStore, commitPath) = try await makeConfiguredStore(
            "commit-failure",
            probe: { $0 == .commit ? full : nil }
        )
        defer { Self.cleanup(commitPath) }
        await #expect(throws: CausalGraphStorageAdmissionError.self) {
            try await commitStore.upsertBatch(
                entities: [Self.entity("commit-row")], edges: [])
        }
        #expect(try await commitStore.entity(id: "commit-row") == nil,
                "failed COMMIT must never report or retain the row")
        await commitStore.close()

        let rollbackStorage = CausalGraphInjectedSQLiteFailure(
            resultCode: SQLITE_IOERR,
            extendedResultCode: SQLITE_IOERR | Int32(3 << 8),
            systemErrno: ENOSPC
        )
        let (rollbackStore, rollbackPath) = try await makeConfiguredStore(
            "rollback-failure",
            probe: { operation in
                switch operation {
                case .commit:
                    return CausalGraphInjectedSQLiteFailure(resultCode: SQLITE_BUSY)
                case .rollback:
                    return rollbackStorage
                case .begin:
                    return nil
                }
            }
        )
        defer { Self.cleanup(rollbackPath) }
        await #expect(throws: CausalGraphStorageAdmissionError.self) {
            try await rollbackStore.upsertBatch(
                entities: [Self.entity("rollback-row")], edges: [])
        }
        await #expect(throws: CausalGraphStoreError.self) {
            _ = try await rollbackStore.entity(id: "rollback-row")
        }
        let reopened = try await SQLiteCausalGraphStore(databasePath: rollbackPath)
        #expect(try await reopened.entity(id: "rollback-row") == nil,
                "poisoned connection close must roll back the uncertain transaction")
        await reopened.close()
    }

    @Test("max_page_count setup propagates errors and rejects mismatch")
    func maximumPageCountSetupIsChecked() async throws {
        #expect(throws: CausalGraphStoreError.self) {
            try SQLiteCausalGraphStore.validateInstalledMaximumPageCount(
                requestedPages: 100,
                currentPages: 50,
                installedPages: 99
            )
        }

        for operation in [
            CausalGraphPageLimitOperation.readPageSize,
            .readPageCount,
            .installLimit,
        ] {
            let path = Self.tempPath("page-limit-\(operation.rawValue)")
            defer { Self.cleanup(path) }
            await #expect(throws: CausalGraphStorageAdmissionError.self) {
                _ = try await SQLiteCausalGraphStore(
                    databasePath: path,
                    maxFootprintBytes: 64 * Self.mib,
                    footprintProbe: { _ in Self.mib },
                    pageLimitFailureProbe: { point in
                        point == operation
                            ? CausalGraphInjectedSQLiteFailure(resultCode: SQLITE_FULL)
                            : nil
                    }
                )
            }
        }

        let corruptPath = Self.tempPath("page-limit-corrupt")
        defer { Self.cleanup(corruptPath) }
        do {
            _ = try await SQLiteCausalGraphStore(
                databasePath: corruptPath,
                pageLimitFailureProbe: { point in
                    point == .installLimit
                        ? CausalGraphInjectedSQLiteFailure(resultCode: SQLITE_CORRUPT)
                        : nil
                }
            )
            Issue.record("injected max_page_count corruption was ignored")
        } catch let error as CausalGraphStoreError {
            let metadata = try #require(error.sqliteFailureMetadata)
            #expect((metadata.extendedResultCode & 0xFF) == SQLITE_CORRUPT)
        }
    }

    @Test("Storage safety wiring cannot drift around the central gate")
    func storageSafetySourceWiring() throws {
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        func source(_ relativePath: String) throws -> String {
            try String(
                contentsOf: root.appendingPathComponent(relativePath),
                encoding: .utf8
            )
        }

        let store = try source("Sources/MacCrabCore/Storage/SQLiteCausalGraphStore.swift")
        #expect(store.contains("private static let traceCascadeBatchSize = 8"))
        #expect(store.contains("traceCascadeNarrowChildBatchSize"))
        #expect(store.contains("maxTraceChildRows: Int = 16_384"))
        #expect(store.contains("min(requestedBatchSize, Self.substrateDeleteBatchSize)"))
        #expect(store.components(separatedBy: "batchedCascadeDeleteTraces(").count - 1 >= 5,
                "all public/recovery trace delete paths must share the bounded helper")
        let recoveryStart = try #require(store.range(
            of: "public func recoverStorageBudget("))
        let recoveryEnd = try #require(store.range(
            of: "private struct RecoveryTraceSelection",
            range: recoveryStart.upperBound..<store.endIndex))
        let recoverySource = String(store[
            recoveryStart.lowerBound..<recoveryEnd.lowerBound])
        #expect(!recoverySource.contains("olderThan: nil"),
                "storage pressure must never evict traces newer than an explicit cutoff")
        #expect(!recoverySource.contains("cutoff: nil"),
                "storage pressure must never evict graph substrate newer than an explicit cutoff")
        #expect(recoverySource.contains("eligibleBacklogRemaining"),
                "the daemon must tighten from post-pass backlog state, not row progress")
        #expect(store.contains("guard !recovering else { return result() }"),
                "recovery must remain single-flight across actor yields")
        let openCall = try #require(store.range(of: "try openDatabase(forceReadOnly: forceReadOnly)"))
        let migration = try #require(store.range(of: "try applyMigrations()"))
        #expect(openCall.lowerBound < migration.lowerBound)
        #expect(store.contains("Earliest point at which the handle exists: install the main-file"))
        #expect(store.contains("hasUsableRuntimeSchema()"),
                "over-budget inherited stores must defer growth migrations")
        #expect(store.contains("deferredMigrationsPending"))
        #expect(store.contains("verifyRequiredMigrationObjects"),
                "growth must not resume on an unchecked deferred migration")
        #expect(store.contains("try throwSQLiteFailure"),
                "SQLite FULL/ENOSPC must re-enter typed admission")
        #expect(store.components(
            separatedBy: "SQLiteOpenPathPolicy.open("
        ).count - 1 >= 3,
                "RW, requested-RO, and fallback-RO opens must share the hardened path gate")
        let openPolicy = try source(
            "Sources/MacCrabCore/Storage/SQLiteOpenPathPolicy.swift"
        )
        #expect(openPolicy.contains("flags | SQLITE_OPEN_NOFOLLOW"),
                "the shared SQLite path gate must refuse symlinks")
        #expect(store.contains("validateSQLiteFileDescriptor"))
        #expect(store.contains("Darwin.fstat"))
        #expect(store.contains("O_EXCL | O_CLOEXEC | O_NOFOLLOW"),
                "missing DB leaves must be created atomically under the trusted dirfd")
        #expect(!store.contains("rootSticky"),
                "sticky writable ancestors permit attacker-precreated leaves")
        #expect(store.contains("BEGIN IMMEDIATE"),
                "global continuity and cascade head/read mutations need cross-connection serialization")
        #expect(store.contains("idx_hash_chain_global_seq"),
                "legacy continuity queries need a global sequence seek index")
        #expect(store.contains("duplicatedGlobalHeadSequence"),
                "append must fail closed on an inherited duplicated head")
        #expect(store.contains("boundedCascadeSelection"))
        #expect(store.contains("octet_length("),
                "cascade transactions must account for inherited TEXT/BLOB bytes")
        #expect(!store.contains("String(reflecting:"),
                "hot-path mutation sizing must use explicit UTF-8 accounting")
        #expect(store.contains("Darwin.lstat"),
                "exact footprint probe must avoid FileManager double syscalls")
        #expect(store.contains("guard maxFootprintBytes == nil, freeSpaceFloorBytes == nil"),
                "configured live stores must reject full VACUUM")
        #expect(store.contains("let safeByReserve"),
                "configured incremental vacuum must be reserve-bounded")
        #expect(store.contains("freeSpaceAdmissionRequirement"),
                "status and writes must share stable floor-plus-reserve headroom")
        #expect(store.components(separatedBy: "rollbackAndRethrow(").count - 1 >= 5,
                "every explicit transaction must use checked rollback")
        #expect(!store.contains("sqlite3_exec(db, \"ROLLBACK\""),
                "unchecked rollback can erase FULL/IOERR metadata")
        #expect(store.contains("select trace IDs for recovery"),
                "selection step errors must not become a partial delete set")
        #expect(store.contains("validateInstalledMaximumPageCount"),
                "SQLite's hard page backstop must be read back and verified")

        let pragmas = try source("Sources/MacCrabCore/Storage/StoragePragmas.swift")
        #expect(pragmas.contains("SQLiteFailureMetadata"),
                "incremental vacuum failures must preserve VFS errno")
        #expect(!pragmas.contains("sqlite3_wal_checkpoint_v2"),
                "the path-agnostic vacuum primitive cannot admit checkpoint headroom")
        #expect(store.components(separatedBy: "sqlite3_wal_checkpoint_v2").count - 1 == 1,
                "all TraceGraph checkpoints must stay behind the centralized fresh gate")

        let materializer = try source("Sources/MacCrabCore/TraceGraph/TraceMaterializer.swift")
        #expect(materializer.contains("catch let admission as CausalGraphStorageAdmissionError"))
        #expect(materializer.contains("catch is CausalGraphStorageAdmissionError"))
        let rolling = try source("Sources/MacCrabCore/TraceGraph/RollingCausalGraph.swift")
        #expect(rolling.contains("catch is CausalGraphStorageAdmissionError"))
        #expect(rolling.contains("materialization failed for anchor"),
                "generic materialization errors must remain visible")
        let bridge = try source("Sources/MacCrabCore/TraceGraph/EventToRollingCausalGraphBridge.swift")
        #expect(bridge.contains("catch is CausalGraphStorageAdmissionError"))
        #expect(bridge.contains("rolling graph ingest failed"),
                "generic ingest errors must remain visible")

        let timers = try source("Sources/MacCrabAgentKit/DaemonTimers.swift")
        #expect(!timers.contains("maccrabctl maintenance vacuum tracegraph"),
                "operator warning must not name a nonexistent command")
        let setup = try source("Sources/MacCrabAgentKit/DaemonSetup.swift")
        let signals = try source("Sources/MacCrabAgentKit/SignalHandlers.swift")
        #expect(setup.contains("TraceGraphStoragePolicy.capBytes"))
        #expect(setup.contains("TraceGraphStoragePolicy.freeSpaceFloorBytes"))
        #expect(signals.contains("TraceGraphStoragePolicy.capBytes"))
        #expect(signals.contains("TraceGraphStoragePolicy.freeSpaceFloorBytes"))
    }

    @Test("Admission-enabled versus disabled hot-path diagnostic")
    func admissionProbeThroughputDiagnostic() async throws {
        let disabledPath = Self.tempPath("throughput-disabled")
        let enabledPath = Self.tempPath("throughput-enabled")
        defer {
            Self.cleanup(disabledPath)
            Self.cleanup(enabledPath)
        }
        let iterations = 1_000

        let disabled = try await SQLiteCausalGraphStore(databasePath: disabledPath)
        let disabledStart = Date()
        for index in 0..<iterations {
            try await disabled.upsertEntity(Self.entity("disabled-\(index)"))
        }
        let disabledSeconds = Date().timeIntervalSince(disabledStart)
        #expect(try await disabled.entity(id: "disabled-999") != nil)
        await disabled.close()

        // Use the real Darwin DB/WAL/SHM probe and Darwin statfs probe;
        // the large cap/floor keep all writes admitted without caching either.
        let enabled = try await SQLiteCausalGraphStore(
            databasePath: enabledPath,
            maxFootprintBytes: 1_000_000 * Self.mib,
            freeSpaceFloorBytes: 1
        )
        let enabledStart = Date()
        for index in 0..<iterations {
            try await enabled.upsertEntity(Self.entity("enabled-\(index)"))
        }
        let enabledSeconds = Date().timeIntervalSince(enabledStart)
        #expect(try await enabled.entity(id: "enabled-999") != nil)
        await enabled.close()

        let disabledMicros = disabledSeconds * 1_000_000 / Double(iterations)
        let enabledMicros = enabledSeconds * 1_000_000 / Double(iterations)
        let ratio = enabledSeconds / max(disabledSeconds, 0.000_001)
        print(String(format:
            "TRACEGRAPH_ADMISSION_BENCH disabled=%.1f us/event enabled=%.1f us/event ratio=%.2fx iterations=%d",
            disabledMicros, enabledMicros, ratio, iterations))
    }
}
