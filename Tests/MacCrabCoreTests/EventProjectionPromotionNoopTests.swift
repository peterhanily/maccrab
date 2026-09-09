import Foundation
import CSQLCipher
import Testing
@testable import MacCrabCore

@Suite("Verified promotion no-ops on omitted terminal projections")
struct EventProjectionPromotionNoopTests {
    private static let cap: Int64 = 256 * 1_048_576

    private struct Fixture {
        let directory: URL
        let path: String
        let store: EventStore
        let budget: EventPipelineLiveMemoryBudget
        let base: EventJournalIngressPreparation
        let terminal: Event
    }

    private func match(_ suffix: String = "first") -> RuleMatch {
        RuleMatch(
            ruleId: "promotion-noop-\(suffix)", ruleName: "Reviewed \(suffix)",
            severity: .high, description: "Ordinary promotion fixture"
        )
    }

    private func fixture(canary: Bool = false, compact: Bool = true) async throws -> Fixture {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("projection-noop-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        let path = directory.appendingPathComponent("events.db").path
        let budget = EventPipelineLiveMemoryBudget.isolatedProductionEquivalentForTesting()
        let store = try EventStore(
            path: path,
            storagePolicy: SQLitePersistentStorePolicy(
                maxFootprintBytes: Self.cap, freeSpaceFloorBytes: 0,
                transactionReserveBytes: SQLitePersistentStorePolicy.eventTransactionReserveBytes,
                storageVolumePath: directory.path
            ),
            liveMemoryBudget: budget
        )
        try #require(try await store.recoverJournalBeforeProducers().complete)
        let timestamp = Date().addingTimeInterval(-10)
        let arguments = [CoverageCanary.spawnBinaryPath]
            + (canary ? [CoverageCanary.makeNonce()] : [])
        var event = Event(
            timestamp: timestamp, eventCategory: .process,
            eventType: .start, eventAction: "exec",
            process: MacCrabCore.ProcessInfo(
                pid: 100, ppid: 1, rpid: 1, name: "true",
                executable: CoverageCanary.spawnBinaryPath,
                commandLine: arguments.joined(separator: " "), args: arguments,
                workingDirectory: "/", userId: 0, userName: "root", groupId: 0,
                startTime: timestamp, ancestors: [], isPlatformBinary: true
            )
        )
        if !compact {
            event.ruleMatches = [match()]
            event.severity = .high
        }
        let base = try EventJournalAdmissionValidator.prepare(event)
        let inserted = try await store.insert(preparedEvents: [base], lane: .priority)
        try #require(inserted.persistedCount == 1)
        var terminal = base.event
        if compact {
            terminal.ruleMatches = [match()]
            terminal.severity = .high
            terminal.enrichments["reviewed"] = "terminal"
            if canary {
                // A legitimate quota omission, rather than deleting the
                // canary behind its ledger, exercises the canary exclusion.
                terminal.enrichments["fixture_padding"] = String(
                    repeating: "g", count: EventStore.projectionBytesPerBucket * 2
                )
            }
            let preparation = EventTerminalDeltaStoragePreparation(
                compacting: try EventTerminalDeltaValidator.prepare(
                    base: base.event, terminal: terminal,
                    baseCanonicalSHA256: base.canonicalSHA256,
                    sourceIdentitySHA256: base.sourceIdentitySHA256
                )
            )
            let workspace = try #require(budget.tryAcquire(
                bytes: EventJournalCodec.maximumWorkspaceBytes,
                owner: .eventStoreWorkspace
            ))
            let result = try await store.appendTerminalDeltas(
                preparedDeltas: [preparation], lane: .priority, workspaceLease: workspace
            )
            try #require(result.outcomes.first?.disposition == .inserted)
            withExtendedLifetime(workspace) {}
        }
        try #require(try await store.exactEventSnapshot(id: event.id).event == terminal)
        return Fixture(
            directory: directory, path: path, store: store, budget: budget,
            base: base, terminal: terminal
        )
    }

    private func withDatabase<T>(
        _ path: String, writable: Bool = false,
        _ body: (OpaquePointer) throws -> T
    ) throws -> T {
        var handle: OpaquePointer?
        let rc = sqlite3_open_v2(
            path, &handle,
            (writable ? SQLITE_OPEN_READWRITE : SQLITE_OPEN_READONLY) | SQLITE_OPEN_FULLMUTEX,
            nil
        )
        guard rc == SQLITE_OK, let db = handle else {
            if let handle { sqlite3_close(handle) }
            throw NSError(domain: "PromotionNoopFixture", code: Int(rc))
        }
        defer { sqlite3_close(db) }
        return try body(db)
    }

    private func scalar(_ sql: String, on db: OpaquePointer) throws -> Int64 {
        var raw: OpaquePointer?
        try #require(sqlite3_prepare_v2(db, sql, -1, &raw, nil) == SQLITE_OK)
        let statement = try #require(raw)
        defer { sqlite3_finalize(statement) }
        try #require(sqlite3_step(statement) == SQLITE_ROW)
        return sqlite3_column_int64(statement, 0)
    }

    private func refuseWrites(_ store: EventStore) async throws {
        try await store.setStorageAdmissionProbesForTesting(
            footprint: { _ in Self.cap }, freeSpace: { _ in Int64.max / 4 }
        )
        do {
            _ = try await store.reprobeStorageAdmissionForWrite(lane: .priority)
            Issue.record("Fixture did not refuse actual write admission")
        } catch let error as SQLitePersistentStoreAdmissionError {
            guard case .footprintLimit = error else { throw error }
        }
    }

    @Test("Already-reviewed compact terminal needs no write admission or generation advance")
    func omittedTerminalIsReadOnlyUnderPressure() async throws {
        let f = try await fixture()
        defer { try? FileManager.default.removeItem(at: f.directory) }
        try withDatabase(f.path) { (db: OpaquePointer) throws -> Void in
            #expect(try scalar("SELECT COUNT(*) FROM events", on: db) == 0)
            #expect(try scalar("SELECT COUNT(*) FROM event_journal_terminal_revisions", on: db) == 1)
        }
        try await refuseWrites(f.store)
        let exact = try await f.store.exactEventSnapshot(id: f.terminal.id)
        let before = try await f.store.storageAdmissionConnectionStateForTesting()
        for requested in [[match(), match()], []] {
            let result = try await f.store.promoteProjection(
                eventID: f.terminal.id, reviewedMatches: requested
            )
            #expect(result.insertedMatchCount == 0)
            #expect(result.totalReviewedMatchCount == 1)
            #expect(!result.projectionMaterialized)
            #expect(result.evidenceGap == nil)
            #expect(result.storageMutationGeneration == exact.mutationGeneration)
        }
        let after = try await f.store.storageAdmissionConnectionStateForTesting()
        #expect(after.totalChanges == before.totalChanges)
        #expect(!after.inTransaction)
        #expect(try await f.store.exactEventSnapshot(id: f.terminal.id) == exact)
        try withDatabase(f.path) { (db: OpaquePointer) throws -> Void in
            #expect(try scalar("SELECT COUNT(*) FROM event_journal_projection_promotions", on: db) == 0)
            #expect(try scalar("SELECT COUNT(*) FROM event_journal_payload_poison", on: db) == 0)
            #expect(try scalar("SELECT SUM(materialized_count) FROM event_projection_coverage", on: db) == 0)
            #expect(try scalar("SELECT SUM(considered_count) FROM event_projection_coverage", on: db) == 1)
        }
        #expect(f.budget.snapshot().withinCapacity)
        #expect(f.budget.snapshot().leasesConserved)
    }

    @Test("New evidence, existing rows and omitted canaries retain write admission", arguments: ["new-match", "existing-row", "canary"])
    func requiredReconciliationCannotUseNoop(kind: String) async throws {
        let f = try await fixture(canary: kind == "canary", compact: kind != "existing-row")
        defer { try? FileManager.default.removeItem(at: f.directory) }
        try withDatabase(f.path) { (db: OpaquePointer) throws -> Void in
            #expect(try scalar("SELECT COUNT(*) FROM events", on: db)
                == (kind == "existing-row" ? 1 : 0))
        }
        #expect(NoiseFilter.isCoverageCanaryProbe(event: f.terminal) == (kind == "canary"))
        let exact = try await f.store.exactEventSnapshot(id: f.terminal.id)
        try await refuseWrites(f.store)
        let before = try await f.store.storageAdmissionConnectionStateForTesting()
        do {
            _ = try await f.store.promoteProjection(
                eventID: f.terminal.id,
                reviewedMatches: [kind == "new-match" ? match("second") : match()]
            )
            Issue.record("Required reconciliation bypassed write admission: \(kind)")
        } catch let error as SQLitePersistentStoreAdmissionError {
            guard case .footprintLimit = error else { throw error }
        }
        let after = try await f.store.storageAdmissionConnectionStateForTesting()
        #expect(after.totalChanges == before.totalChanges)
        #expect(!after.inTransaction)
        #expect(try await f.store.exactEventSnapshot(id: f.terminal.id) == exact)
        #expect(try await f.store.payloadPoisonTotalSnapshot() == 0)
    }

    @Test("An independent writer's reviewed union is reread before a no-op")
    func independentWriterRefreshesExactUnion() async throws {
        let f = try await fixture()
        defer { try? FileManager.default.removeItem(at: f.directory) }
        let warm = try await f.store.promoteProjection(
            eventID: f.terminal.id, reviewedMatches: [match()]
        )
        let other = try EventStore(path: f.path, liveMemoryBudget: f.budget)
        let changed = try await other.promoteProjection(
            eventID: f.terminal.id, reviewedMatches: [match("second")]
        )
        #expect(changed.insertedMatchCount == 1)
        #expect(changed.totalReviewedMatchCount == 2)
        #expect(!changed.projectionMaterialized)
        #expect(changed.storageMutationGeneration > warm.storageMutationGeneration)
        let before = try await f.store.storageAdmissionConnectionStateForTesting()
        let result = try await f.store.promoteProjection(
            eventID: f.terminal.id, reviewedMatches: [match(), match("second")]
        )
        #expect(result.insertedMatchCount == 0)
        #expect(result.totalReviewedMatchCount == 2)
        #expect(result.storageMutationGeneration == changed.storageMutationGeneration)
        let after = try await f.store.storageAdmissionConnectionStateForTesting()
        #expect(after.totalChanges == before.totalChanges)
        var expected = f.terminal
        expected.ruleMatches = ReviewedRuleMatches.normalized([match(), match("second")])
        #expect(try await f.store.exactEventSnapshot(id: expected.id).event == expected)
    }

    @Test("Missing materialized rows and invalid omission checksums remain errors", arguments: [false, true])
    func inconsistentOmissionCannotBeNoop(invalidChecksum: Bool) async throws {
        let f = try await fixture(compact: invalidChecksum)
        defer { try? FileManager.default.removeItem(at: f.directory) }
        // Warm the in-memory locator before a distinct SQLite handle changes
        // storage, so the test also excludes relying on a prior verified row.
        _ = try await f.store.exactEventSnapshot(id: f.terminal.id)
        try withDatabase(f.path, writable: true) { (db: OpaquePointer) throws -> Void in
            let sql = invalidChecksum
                ? "UPDATE event_journal_blocks SET projection_dispositions_sha256 = zeroblob(32)"
                : "DELETE FROM events"
            try #require(sqlite3_exec(db, sql, nil, nil, nil) == SQLITE_OK)
        }
        let before = try await f.store.storageAdmissionConnectionStateForTesting()
        do {
            _ = try await f.store.promoteProjection(eventID: f.terminal.id, reviewedMatches: [match()])
            Issue.record("Inconsistent projection metadata was accepted as unchanged")
        } catch let error as EventStoreError {
            guard case .decodingFailed = error else { throw error }
        }
        let after = try await f.store.storageAdmissionConnectionStateForTesting()
        #expect(after.totalChanges == before.totalChanges)
        #expect(!after.inTransaction)
    }

    @Test("A poisoned compact terminal still returns its evidence gap")
    func poisonCannotBecomeExactNoop() async throws {
        let f = try await fixture(compact: false)
        defer { try? FileManager.default.removeItem(at: f.directory) }
        var terminal = f.base.event
        terminal.enrichments["oversized"] = String(
            repeating: "g", count: EventJournalAdmissionValidator.maximumPreflightStringBytes + 1
        )
        let preparation = EventTerminalDeltaStoragePreparation(
            compacting: try EventTerminalDeltaValidator.prepare(
                base: f.base.event, terminal: terminal,
                baseCanonicalSHA256: f.base.canonicalSHA256,
                sourceIdentitySHA256: f.base.sourceIdentitySHA256
            )
        )
        let poison = try #require(preparation.overflow)
        let workspace = try #require(f.budget.tryAcquire(
            bytes: EventJournalCodec.maximumWorkspaceBytes, owner: .eventStoreWorkspace
        ))
        let appended = try await f.store.appendTerminalDeltas(
            preparedDeltas: [preparation], lane: .priority, workspaceLease: workspace
        )
        #expect(appended.outcomes.first?.disposition == .poisoned(poison))
        let result = try await f.store.promoteProjection(eventID: f.terminal.id, reviewedMatches: [match()])
        #expect(result.evidenceGap != nil)
        #expect(!result.projectionMaterialized)
        #expect(result.insertedMatchCount == 0)
        #expect(try await f.store.payloadPoisonTotalSnapshot() == 1)
        withExtendedLifetime(workspace) {}
    }
}
