import Foundation
import CSQLCipher
import Testing
@testable import MacCrabCore
@testable import MacCrabAgentKit

@Suite("Coverage canary FTS proof under bounded storage and memory pressure")
struct CoverageCanaryProjectionTests {
    private final class LeaseBox: @unchecked Sendable {
        private let lock = NSLock()
        private var lease: EventPipelineMemoryLease?

        func store(_ value: EventPipelineMemoryLease?) {
            lock.lock()
            lease = value
            lock.unlock()
        }

        var bytes: Int {
            lock.lock()
            defer { lock.unlock() }
            return lease?.bytes ?? 0
        }
    }

    private struct ProjectionRow {
        let id: UUID
        let rank: Int
        let bytes: Int
        let bucket: Int64
    }

    private func event(
        id: UUID = UUID(), nonce: String? = nil, name: String = "true",
        timestamp: Date = Date().addingTimeInterval(-10)
    ) -> Event {
        let arguments = [CoverageCanary.spawnBinaryPath] + (nonce.map { [$0] } ?? [])
        return Event(
            id: id, timestamp: timestamp,
            eventCategory: .process, eventType: .start, eventAction: "exec",
            process: MacCrabCore.ProcessInfo(
                pid: 100, ppid: 1, rpid: 1, name: name,
                executable: CoverageCanary.spawnBinaryPath,
                commandLine: arguments.joined(separator: " "), args: arguments,
                workingDirectory: "/", userId: 0, userName: "root", groupId: 0,
                startTime: timestamp, ancestors: [], isPlatformBinary: true
            )
        )
    }

    private func directory() throws -> URL {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("canary-projection-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        return directory
    }

    private func withDatabase<T>(
        path: String,
        writable: Bool = false,
        _ body: (OpaquePointer) throws -> T
    ) throws -> T {
        var raw: OpaquePointer?
        let flags = (writable ? SQLITE_OPEN_READWRITE : SQLITE_OPEN_READONLY)
            | SQLITE_OPEN_FULLMUTEX
        let rc = sqlite3_open_v2(path, &raw, flags, nil)
        guard rc == SQLITE_OK, let db = raw else {
            if let raw { sqlite3_close(raw) }
            throw NSError(domain: "CanaryProjectionFixture", code: Int(rc))
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

    private func projections(path: String) throws -> [ProjectionRow] {
        try withDatabase(path: path) { db in
            var raw: OpaquePointer?
            try #require(sqlite3_prepare_v2(db, """
                SELECT id, projection_rank, projection_estimated_bytes, projection_bucket
                FROM events WHERE journal_block_id IS NOT NULL
                """, -1, &raw, nil) == SQLITE_OK)
            let statement = try #require(raw)
            defer { sqlite3_finalize(statement) }
            var rows: [ProjectionRow] = []
            while true {
                let rc = sqlite3_step(statement)
                if rc == SQLITE_DONE { return rows }
                try #require(rc == SQLITE_ROW)
                let text = try #require(sqlite3_column_text(statement, 0))
                let id = try #require(UUID(uuidString: String(cString: text)))
                rows.append(ProjectionRow(
                    id: id,
                    rank: Int(sqlite3_column_int(statement, 1)),
                    bytes: Int(sqlite3_column_int64(statement, 2)),
                    bucket: sqlite3_column_int64(statement, 3)
                ))
            }
        }
    }

    private func assertConservedCoverage(path: String, materialized: Int, replaced: Int, quota: Int) throws {
        try withDatabase(path: path) { (db: OpaquePointer) throws -> Void in
            for table in ["event_projection_coverage", "event_projection_block_coverage"] {
                #expect(try scalar("SELECT SUM(considered_count) FROM \(table)", on: db) == 3)
                #expect(try scalar("SELECT SUM(materialized_count) FROM \(table)", on: db) == materialized)
                #expect(try scalar("SELECT SUM(omitted_replaced_count) FROM \(table)", on: db) == replaced)
                #expect(try scalar("SELECT SUM(replacement_total) FROM \(table)", on: db) == replaced)
                #expect(try scalar("SELECT SUM(omitted_quota_count) FROM \(table)", on: db) == quota)
                #expect(try scalar("""
                    SELECT COUNT(*) FROM \(table)
                    WHERE considered_count != materialized_count + omitted_quota_count
                        + omitted_replaced_count + omitted_physical_count
                        + omitted_external_count + omitted_migration_count + pending_count
                    """, on: db) == 0)
                #expect(try scalar("""
                    SELECT SUM(omitted_physical_count + omitted_external_count
                        + omitted_migration_count + pending_count) FROM \(table)
                    """, on: db) == 0)
                #expect(try scalar("SELECT SUM(materialized_bytes) FROM \(table)", on: db)
                    == (try scalar("SELECT SUM(projection_estimated_bytes) FROM events WHERE journal_block_id IS NOT NULL", on: db)))
            }
            #expect(try scalar("SELECT COUNT(*) FROM event_journal_payload_poison", on: db) == 0)
            #expect(try scalar("SELECT COUNT(*) FROM event_journal_inherited_loss", on: db) == 0)
        }
    }

    @Test("Terminal canary growth replaces a lower-ranked row and conserves exact evidence", arguments: [false, true])
    func terminalGrowthKeepsCanarySearchable(compactDelta: Bool) async throws {
        let directory = try directory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let path = directory.appendingPathComponent("events.db").path
        let nonce = CoverageCanary.makeNonce()
        let canary = event(nonce: nonce)
        let ordinary = [
            event(name: "fixture-a", timestamp: canary.timestamp),
            event(name: "fixture-b", timestamp: canary.timestamp),
        ]
        var terminal = canary

        func exercise() async throws {
            let budget = EventPipelineLiveMemoryBudget.isolatedProductionEquivalentForTesting()
            let store = try EventStore(path: path, liveMemoryBudget: budget)
            _ = try await store.recoverJournalBeforeProducers()
            let writer = BatchedEventWriter(
                store: store, flushThreshold: 100, liveMemoryBudget: budget
            )
            let baseOutcome = try #require(await writer.prepareAndEnqueueBase(canary))
            let receipt = try #require(baseOutcome.admission)
            for neighbor in ordinary {
                let admitted = try #require(await writer.prepareAndEnqueueBase(neighbor))
                _ = try #require(admitted.admission)
            }
            await writer.flushPartial()
            #expect(try await store.count() == 3)
            let before = try projections(path: path)
            try #require(before.count == 3)
            try #require(Set(before.map(\.bucket)).count == 1)
            let canaryRow = try #require(before.first { $0.id == canary.id })
            #expect(canaryRow.rank == 0)
            let neighbors = before.filter { $0.id != canary.id }
            #expect(neighbors.allSatisfy { $0.rank > canaryRow.rank })
            let usage = before.reduce(0) { $0 + $1.bytes }
            let spare = EventStore.projectionBytesPerBucket - usage
            try #require(spare >= 0)
            // ASCII padding increases the encoded projection by at least this
            // many bytes. The original bucket cannot hold the revision, while
            // removing one measured ordinary row must leave enough room.
            let padding = spare + 512
            try #require(canaryRow.bytes + padding + 128 < EventStore.projectionBytesPerBucket)
            try #require(neighbors.allSatisfy { $0.bytes > 512 + 128 })
            terminal.enrichments["fixture_padding"] = String(repeating: "g", count: padding)
            #expect(try await store.containsProjectedFTSMatch(
                text: nonce, since: canary.timestamp.addingTimeInterval(-1), until: Date()
            ))
            if compactDelta {
                // This is the production EventLoop -> writer -> adopted S
                // workspace -> appendTerminalDeltas seam. Previously every
                // changed delta removed the canary's sparse row, even when
                // its exact terminal and all lower-ranked neighbors fit.
                let proof = await writer.prepareAndSettleTerminalDelta(
                    base: canary, terminal: terminal, lane: .priority,
                    admission: receipt, timeout: .seconds(5)
                )
                let expected = try EventJournalAdmissionValidator.prepare(terminal)
                #expect(proof.status == .verified)
                #expect(proof.terminalCanonicalSHA256 == expected.canonicalSHA256)
                #expect(proof.terminalCanonicalByteCount == expected.canonicalJSON.count)
                let telemetry = await writer.telemetrySnapshot()
                #expect(telemetry.terminalRevisionDurableCount == 1)
                #expect(telemetry.terminalRevisionDroppedCount == 0)
                #expect(telemetry.terminalRevisionPoisonedCount == 0)
                #expect(telemetry.terminalRevisionConservationHolds)
            } else {
                let outcome = try await store.appendTerminalRevision(terminal, lane: .priority)
                #expect(outcome == .inserted(eventID: canary.id))
            }
            await writer.shutdown()
            #expect(budget.snapshot().withinCapacity)
            #expect(budget.snapshot().leasesConserved)
            try withDatabase(path: path) { (db: OpaquePointer) throws -> Void in
                #expect(try scalar("SELECT COUNT(*) FROM event_journal_terminal_revisions", on: db) == 1)
            }
            #expect(try await store.containsProjectedFTSMatch(
                text: nonce, since: canary.timestamp.addingTimeInterval(-1), until: Date()
            ))
            #expect(await DaemonTimers.canaryPresentInDB(
                eventStore: store, nonce: nonce, since: canary.timestamp.addingTimeInterval(-1)
            ) == .present)
            #expect(try await store.searchSnapshot(
                text: nonce, since: canary.timestamp.addingTimeInterval(-1),
                until: Date(), limit: 1
            ).events == [terminal])
            let after = try projections(path: path)
            #expect(after.count == 2)
            #expect(after.contains { $0.id == canary.id })
            #expect(after.reduce(0) { $0 + $1.bytes } <= EventStore.projectionBytesPerBucket)
            for expected in [terminal] + ordinary {
                #expect(try await store.exactEventSnapshot(id: expected.id).event == expected)
            }
            #expect(try await store.count() == 3)
            try assertConservedCoverage(path: path, materialized: 2, replaced: 1, quota: 0)
            // The entire fresh fixture family is below the projection limit,
            // so its projection allocation necessarily is too.
            #expect(try SQLitePersistentStoreAdmission.measureFamily(path)
                <= EventStore.projectionPhysicalLimitBytes)
        }
        try await exercise()

        let reopened = try EventStore(path: path)
        #expect(try await reopened.recoverJournalBeforeProducers().complete)
        #expect(try await reopened.containsProjectedFTSMatch(
            text: nonce, since: canary.timestamp.addingTimeInterval(-1), until: Date()
        ))
        for expected in [terminal] + ordinary {
            #expect(try await reopened.exactEventSnapshot(id: expected.id).event == expected)
        }
        try assertConservedCoverage(path: path, materialized: 2, replaced: 1, quota: 0)
    }

    @Test("An oversized canary revision omits only itself without bypassing quota", arguments: [false, true])
    func unfitCanaryDoesNotDiscardNeighbors(compactDelta: Bool) async throws {
        let directory = try directory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let path = directory.appendingPathComponent("events.db").path
        let budget = EventPipelineLiveMemoryBudget.isolatedProductionEquivalentForTesting()
        let store = try EventStore(path: path, liveMemoryBudget: budget)
        _ = try await store.recoverJournalBeforeProducers()
        let nonce = CoverageCanary.makeNonce()
        let canary = event(nonce: nonce)
        let ordinary = [
            event(name: "fixture-a", timestamp: canary.timestamp),
            event(name: "fixture-b", timestamp: canary.timestamp),
        ]
        _ = try await store.insert(events: [canary] + ordinary, lane: .priority)
        try #require(try projections(path: path).count == 3)
        var terminal = canary
        terminal.enrichments["fixture_padding"] = String(
            repeating: "g", count: EventStore.projectionBytesPerBucket * 2
        )
        if compactDelta {
            let base = try EventJournalAdmissionValidator.prepare(canary)
            let prepared = EventTerminalDeltaStoragePreparation(
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
            let outcome = try await store.appendTerminalDeltas(
                preparedDeltas: [prepared], lane: .priority, workspaceLease: workspace
            )
            #expect(outcome.outcomes.first?.disposition == .inserted)
            withExtendedLifetime(workspace) {}
        } else {
            #expect(try await store.appendTerminalRevision(terminal, lane: .priority)
                == .inserted(eventID: canary.id))
        }
        #expect(Set(try projections(path: path).map(\.id)) == Set(ordinary.map(\.id)))
        #expect(try await store.exactEventSnapshot(id: canary.id).event == terminal)
        #expect(await DaemonTimers.canaryPresentInDB(
            eventStore: store, nonce: nonce, since: canary.timestamp.addingTimeInterval(-1)
        ) == .coverageUnknown)
        try assertConservedCoverage(path: path, materialized: 2, replaced: 0, quota: 1)
        #expect(budget.snapshot().withinCapacity)
        #expect(budget.snapshot().leasesConserved)
    }

    @Test("Compact canary ownership refusal releases J credit and retries without losing FTS")
    func compactCanaryOwnershipRefusalIsRetryable() async throws {
        let directory = try directory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let path = directory.appendingPathComponent("events.db").path
        let budget = EventPipelineLiveMemoryBudget.isolatedProductionEquivalentForTesting()
        let store = try EventStore(path: path, liveMemoryBudget: budget)
        _ = try await store.recoverJournalBeforeProducers()
        let nonce = CoverageCanary.makeNonce()
        let base = try EventJournalAdmissionValidator.prepare(event(nonce: nonce))
        _ = try await store.insert(events: [base.event], lane: .priority)
        var terminal = base.event
        terminal.enrichments["reviewed"] = "after-memory-pressure"
        let prepared = EventTerminalDeltaStoragePreparation(
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
        let before = budget.snapshot()
        let blocker = LeaseBox()
        await store.setTerminalDeltaOwnershipGrowthHookForTesting {
            let snapshot = budget.snapshot()
            blocker.store(budget.tryAcquire(
                bytes: snapshot.maximumBytes - snapshot.currentBytes,
                owner: .journalPrepared
            ))
        }
        do {
            _ = try await store.appendTerminalDeltas(
                preparedDeltas: [prepared], lane: .priority, workspaceLease: workspace
            )
            Issue.record("Canary terminal unexpectedly committed while J growth was blocked")
        } catch let error as EventStoreError {
            guard case .memoryLeaseUnavailable = error else { throw error }
        }
        try #require(blocker.bytes > 0)
        // The failed attempt owns no residual base/terminal J credit. Only
        // the fixture blocker and adopted S workspace remain live.
        #expect(budget.snapshot().currentBytes == before.currentBytes + blocker.bytes)
        blocker.store(nil)
        await store.setTerminalDeltaOwnershipGrowthHookForTesting(nil)
        #expect(budget.snapshot().currentBytes == before.currentBytes)
        try withDatabase(path: path) { (db: OpaquePointer) throws -> Void in
            #expect(try scalar("SELECT COUNT(*) FROM event_journal_terminal_revisions", on: db) == 0)
            #expect(try scalar("SELECT COUNT(*) FROM event_journal_payload_poison", on: db) == 0)
        }
        #expect(try await store.exactEventSnapshot(id: base.event.id).event == base.event)

        let result = try await store.appendTerminalDeltas(
            preparedDeltas: [prepared], lane: .priority, workspaceLease: workspace
        )
        #expect(result.outcomes.first?.disposition == .inserted)
        #expect(result.committedTransactionCount == 1)
        #expect(budget.snapshot().currentBytes == before.currentBytes)
        #expect(try await store.exactEventSnapshot(id: base.event.id).event == terminal)
        #expect(try await store.containsProjectedFTSMatch(
            text: nonce, since: base.event.timestamp.addingTimeInterval(-1), until: Date()
        ))
        let retry = try await store.appendTerminalDeltas(
            preparedDeltas: [prepared], lane: .priority, workspaceLease: workspace
        )
        #expect(retry.outcomes.first?.disposition == .alreadyDurable)
        #expect(retry.committedTransactionCount == 0)
        #expect(budget.snapshot().currentBytes == before.currentBytes)
        #expect(budget.snapshot().withinCapacity)
        #expect(budget.snapshot().leasesConserved)
        withExtendedLifetime(workspace) {}
    }

    @Test("A structurally poisoned compact canary removes its stale FTS row and releases J")
    func poisonedCompactCanaryCannotReportPresent() async throws {
        let directory = try directory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let path = directory.appendingPathComponent("events.db").path
        let budget = EventPipelineLiveMemoryBudget.isolatedProductionEquivalentForTesting()
        let store = try EventStore(path: path, liveMemoryBudget: budget)
        _ = try await store.recoverJournalBeforeProducers()
        let nonce = CoverageCanary.makeNonce()
        let base = try EventJournalAdmissionValidator.prepare(event(nonce: nonce))
        _ = try await store.insert(events: [base.event], lane: .priority)
        let prepared: EventTerminalDeltaStoragePreparation = try {
            var terminal = base.event
            terminal.enrichments["fixture_oversized"] = String(
                repeating: "g", count: EventJournalAdmissionValidator.maximumPreflightStringBytes + 1
            )
            return EventTerminalDeltaStoragePreparation(
                compacting: try EventTerminalDeltaValidator.prepare(
                    base: base.event, terminal: terminal,
                    baseCanonicalSHA256: base.canonicalSHA256,
                    sourceIdentitySHA256: base.sourceIdentitySHA256
                )
            )
        }()
        let expectedPoison = try #require(prepared.overflow)
        #expect(prepared.canonicalDeltaJSON.isEmpty)
        let workspace = try #require(budget.tryAcquire(
            bytes: EventJournalCodec.maximumWorkspaceBytes,
            owner: .eventStoreWorkspace
        ))
        let before = budget.snapshot()
        let result = try await store.appendTerminalDeltas(
            preparedDeltas: [prepared], lane: .priority, workspaceLease: workspace
        )
        #expect(result.outcomes.first?.disposition == .poisoned(expectedPoison))
        #expect(result.committedTransactionCount == 1)
        #expect(budget.snapshot().currentBytes == before.currentBytes)
        #expect(budget.snapshot().withinCapacity)
        #expect(budget.snapshot().leasesConserved)
        #expect(try await store.payloadPoisonTotalSnapshot() > 0)
        #expect(try projections(path: path).isEmpty)
        #expect(await DaemonTimers.canaryPresentInDB(
            eventStore: store, nonce: nonce, since: base.event.timestamp.addingTimeInterval(-1)
        ) != .present)
        try withDatabase(path: path) { (db: OpaquePointer) throws -> Void in
            #expect(try scalar("SELECT COUNT(*) FROM event_journal_terminal_revisions", on: db) == 0)
            #expect(try scalar("SELECT SUM(omitted_physical_count) FROM event_projection_coverage", on: db) == 1)
            #expect(try scalar("SELECT SUM(materialized_count) FROM event_projection_coverage", on: db) == 0)
        }
        withExtendedLifetime(workspace) {}
    }

    @Test("Scalar FTS proof succeeds when a full search result lease cannot fit")
    func scalarProofDoesNotNeedArrayResultMemory() async throws {
        let directory = try directory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let path = directory.appendingPathComponent("events.db").path
        let budget = EventPipelineLiveMemoryBudget.isolatedProductionEquivalentForTesting()
        let store = try EventStore(path: path, liveMemoryBudget: budget)
        _ = try await store.recoverJournalBeforeProducers()
        let nonce = CoverageCanary.makeNonce()
        let canary = event(nonce: nonce)
        _ = try await store.insert(events: [canary], lane: .priority)
        let since = canary.timestamp.addingTimeInterval(-1)
        #expect(try await store.containsProjectedFTSMatch(text: nonce, since: since, until: Date()))
        let before = budget.snapshot()
        let remainingResultBytes = 8 * 1_024 * 1_024
        let resultCeiling = before.maximumBytes - before.eventStoreWorkspaceReserveBytes
            + (before.bytesByOwner[EventPipelineMemoryOwner.eventStoreWorkspace.rawValue] ?? 0)
        let heldBytes = resultCeiling - before.currentBytes - remainingResultBytes
        try #require(heldBytes > 0)
        let held = try #require(budget.tryAcquire(bytes: heldBytes, owner: .journalPrepared))
        let search = try await store.searchSnapshot(text: nonce, since: since, until: Date(), limit: 1)
        #expect(search.events.isEmpty)
        #expect(search.gaps.resourceLimitedRecords > 0)
        #expect(!search.isComplete)
        let beforeScalar = budget.snapshot()
        #expect(await DaemonTimers.canaryPresentInDB(
            eventStore: store, nonce: nonce, since: since
        ) == .present)
        #expect(budget.snapshot().currentBytes == beforeScalar.currentBytes)
        #expect(budget.snapshot().withinCapacity)
        #expect(budget.snapshot().leasesConserved)
        withExtendedLifetime(held) {}
    }

    @Test("A LIKE-only projection match cannot satisfy the FTS coverage proof")
    func likeFallbackRemainsUnverified() async throws {
        let directory = try directory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let path = directory.appendingPathComponent("events.db").path
        let store = try EventStore(path: path)
        _ = try await store.recoverJournalBeforeProducers()
        let nonce = CoverageCanary.makeNonce()
        let canary = event(nonce: nonce)
        _ = try await store.insert(events: [canary], lane: .priority)
        // A nonce prefix is a literal substring but not the complete FTS hash
        // token. This exercises the real LIKE fallback without corrupting FTS.
        let prefix = String(nonce.dropLast(8))
        let since = canary.timestamp.addingTimeInterval(-1)
        #expect(!(try await store.containsProjectedFTSMatch(text: prefix, since: since, until: Date())))
        let diagnostic = try await store.searchSnapshot(text: prefix, since: since, until: Date(), limit: 1)
        #expect(diagnostic.events.map(\.id) == [canary.id])
        #expect(await DaemonTimers.canaryPresentInDB(
            eventStore: store, nonce: prefix, since: since
        ) == .coverageUnknown)
        #expect(await DaemonTimers.canaryPresentInDB(
            eventStore: store, nonce: CoverageCanary.makeNonce(), since: since
        ) != .present)
        withExtendedLifetime(diagnostic) {}
    }

    @Test("A delayed source-time probe reconciles only after its ordinary journal insert reaches FTS")
    func lateAdmissionReconcilesTheOriginalProbe() async throws {
        let directory = try directory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let path = directory.appendingPathComponent("events.db").path
        let store = try EventStore(path: path)
        _ = try await store.recoverJournalBeforeProducers()
        let nonce = CoverageCanary.makeNonce()
        // Older than the guaranteed admission window: source time must not
        // silently exclude a delayed event that is admitted to the journal now.
        let canary = event(nonce: nonce, timestamp: Date().addingTimeInterval(-1_200))
        let since = canary.timestamp.addingTimeInterval(-30)
        #expect(!(try await store.containsProjectedFTSMatch(text: nonce, since: since, until: Date())))
        let health = ESDeliveryHealth()
        health.started()
        let token = try #require(health.beginCanary())
        health.finishCanary(token, outcome: .storeQueryUnknown)
        #expect(health.snapshot(lastCallbackUptimeNanoseconds: DispatchTime.now().uptimeNanoseconds).state == .failed)
        let recovered = await DaemonTimers.reconcileCoverageCanary(
            health: health, healthToken: token,
            pause: {
                _ = try await store.insert(events: [canary], lane: .priority)
            },
            isPresent: {
                try await store.containsProjectedFTSMatch(text: nonce, since: since, until: Date())
            }
        )
        #expect(recovered)
        #expect(try await store.exactEventSnapshot(id: canary.id).event == canary)
        let diagnostic = try await store.searchSnapshot(text: nonce, since: since, until: Date(), limit: 1)
        #expect(!diagnostic.requestedWindowComplete)
        #expect(diagnostic.events.map(\.id) == [canary.id])
        let final = health.snapshot(lastCallbackUptimeNanoseconds: DispatchTime.now().uptimeNanoseconds)
        #expect(final.state == .healthy)
        #expect(final.canaryChecksTotal == 1)
        #expect(final.canaryFailuresTotal == 1)
        withExtendedLifetime(diagnostic) {}
    }

    @Test("An actual FTS query failure remains unknown")
    func queryFailureCannotReportPresent() async throws {
        let directory = try directory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let path = directory.appendingPathComponent("events.db").path
        let store = try EventStore(path: path)
        _ = try await store.recoverJournalBeforeProducers()
        let nonce = CoverageCanary.makeNonce()
        let canary = event(nonce: nonce)
        _ = try await store.insert(events: [canary], lane: .priority)
        let since = canary.timestamp.addingTimeInterval(-1)
        #expect(try await store.containsProjectedFTSMatch(text: nonce, since: since, until: Date()))
        // Fault only this disposable fixture after the verified index is warm.
        // The next scalar query must surface the missing FTS table as an error.
        try withDatabase(path: path, writable: true) { db in
            try #require(sqlite3_exec(db, "DROP TABLE events_fts", nil, nil, nil) == SQLITE_OK)
        }
        do {
            _ = try await store.containsProjectedFTSMatch(text: nonce, since: since, until: Date())
            Issue.record("Missing FTS table did not fail the scalar query")
        } catch is EventStoreError {
            // Expected: a real SQLite query/verification failure, not a miss.
        }
        #expect(await DaemonTimers.canaryPresentInDB(
            eventStore: store, nonce: nonce, since: since
        ) == .coverageUnknown)
    }
}
