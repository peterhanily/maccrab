import Foundation
import CSQLCipher
import Testing
@testable import MacCrabCore
@testable import MacCrabAgentKit

@Suite("Shipped EventStore upgrade")
struct EventStoreLegacyUpgradeTests {
    private struct Fixture {
        let directory: URL
        let first: Event
        let last: Event
        let alertID: String
        let evidenceJSON: Data
        let timestampIndexBytes: Int64
        let pageSizeBytes: Int64
        var path: String { directory.appendingPathComponent("events.db").path }
    }

    private func fixture(
        rows: Int,
        incrementalVacuum: Bool = false,
        payloadBytes: Int = 0
    ) throws -> Fixture {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("legacy-event-upgrade-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        var succeeded = false
        defer { if !succeeded { try? FileManager.default.removeItem(at: directory) } }
        let path = directory.appendingPathComponent("events.db").path
        var raw: OpaquePointer?
        #expect(sqlite3_open(path, &raw) == SQLITE_OK)
        let db = try #require(raw)
        defer { sqlite3_close(db) }
        let schemaURL = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
            .appendingPathComponent("fixtures/event-store-v1.21.5.sql")
        let schema = try String(contentsOf: schemaURL, encoding: .utf8)
        if incrementalVacuum {
            try execute("PRAGMA auto_vacuum = INCREMENTAL", on: db)
        }
        try execute(schema, on: db)
        try execute("BEGIN IMMEDIATE", on: db)
        var statement: OpaquePointer?
        let sql = """
            INSERT INTO events (
                id, timestamp, event_category, event_type, event_action, severity,
                process_pid, process_name, process_path, process_commandline, process_ppid, raw_json
            ) VALUES (?1, ?2, 'process', 'start', 'exec', 'informational',
                      4242, 'true', '/usr/bin/true', '/usr/bin/true', 1, ?3)
            """
        #expect(sqlite3_prepare_v2(db, sql, -1, &statement, nil) == SQLITE_OK)
        let insert = try #require(statement)
        defer { sqlite3_finalize(insert) }
        let transient = unsafeBitCast(OpaquePointer(bitPattern: -1)!, to: sqlite3_destructor_type.self)
        let now = Date()
        let process = MacCrabCore.ProcessInfo(
            pid: 4242, ppid: 1, rpid: 1, name: "true", executable: "/usr/bin/true",
            commandLine: "/usr/bin/true", args: ["/usr/bin/true"], workingDirectory: "/",
            userId: 501, userName: "tester", groupId: 20, startTime: now,
            ancestors: [], isPlatformBinary: false
        )
        var first: Event?
        var last: Event?
        var firstJSON: Data?
        let payload = String(repeating: "x", count: payloadBytes)
        for index in 0..<rows {
            var event = Event(
                timestamp: now.addingTimeInterval(-Double(index) / 1_000),
                eventCategory: .process, eventType: .start, eventAction: "exec", process: process
            )
            if payloadBytes > 0 {
                event.enrichments["legacy_fixture_detail"] = payload
            }
            if first == nil { first = event }
            last = event
            let json = String(decoding: try JSONEncoder().encode(event), as: UTF8.self)
            if firstJSON == nil { firstJSON = Data(json.utf8) }
            sqlite3_reset(insert)
            sqlite3_bind_text(insert, 1, event.id.uuidString, -1, transient)
            sqlite3_bind_double(insert, 2, event.timestamp.timeIntervalSince1970)
            sqlite3_bind_text(insert, 3, json, -1, transient)
            guard sqlite3_step(insert) == SQLITE_DONE else {
                throw NSError(domain: "LegacyUpgradeFixture", code: Int(sqlite3_errcode(db)))
            }
        }
        let firstEvent = try #require(first)
        let alertID = UUID().uuidString
        var evidenceStatement: OpaquePointer?
        #expect(sqlite3_prepare_v2(db, """
            INSERT INTO alert_evidence (
                alert_id, id, timestamp, event_category, event_type,
                event_action, severity, process_pid, process_name, process_path, raw_json
            ) SELECT ?1, id, timestamp, event_category, event_type,
                     event_action, severity, process_pid, process_name, process_path, raw_json
              FROM events WHERE id = ?2
            """, -1, &evidenceStatement, nil) == SQLITE_OK)
        let evidenceInsert = try #require(evidenceStatement)
        defer { sqlite3_finalize(evidenceInsert) }
        sqlite3_bind_text(evidenceInsert, 1, alertID, -1, transient)
        sqlite3_bind_text(evidenceInsert, 2, firstEvent.id.uuidString, -1, transient)
        #expect(sqlite3_step(evidenceInsert) == SQLITE_DONE)
        #expect(sqlite3_changes(db) == 1)
        try execute("COMMIT", on: db)
        let result = Fixture(
            directory: directory, first: firstEvent, last: try #require(last),
            alertID: alertID, evidenceJSON: try #require(firstJSON),
            timestampIndexBytes: try scalar(
                "SELECT SUM(pgsize) FROM dbstat WHERE name = 'idx_events_timestamp'", on: db
            ),
            pageSizeBytes: try scalar("PRAGMA page_size", on: db)
        )
        succeeded = true
        return result
    }

    private func scalar(_ sql: String, on db: OpaquePointer) throws -> Int64 {
        var raw: OpaquePointer?
        #expect(sqlite3_prepare_v2(db, sql, -1, &raw, nil) == SQLITE_OK)
        let statement = try #require(raw)
        defer { sqlite3_finalize(statement) }
        #expect(sqlite3_step(statement) == SQLITE_ROW)
        return sqlite3_column_int64(statement, 0)
    }

    private func preservedEvidence(in fixture: Fixture) throws -> Data {
        var raw: OpaquePointer?
        #expect(sqlite3_open_v2(fixture.path, &raw, SQLITE_OPEN_READONLY, nil) == SQLITE_OK)
        let db = try #require(raw)
        defer { sqlite3_close(db) }
        var statement: OpaquePointer?
        #expect(sqlite3_prepare_v2(
            db, "SELECT raw_json FROM alert_evidence WHERE alert_id = ?1", -1, &statement, nil
        ) == SQLITE_OK)
        let query = try #require(statement)
        defer { sqlite3_finalize(query) }
        sqlite3_bind_text(query, 1, fixture.alertID, -1, unsafeBitCast(
            OpaquePointer(bitPattern: -1)!, to: sqlite3_destructor_type.self
        ))
        #expect(sqlite3_step(query) == SQLITE_ROW)
        let bytes = try #require(sqlite3_column_blob(query, 0))
        return Data(bytes: bytes, count: Int(sqlite3_column_bytes(query, 0)))
    }

    private func hasInstalledBarrier(in fixture: Fixture) throws -> Bool {
        var raw: OpaquePointer?
        try #require(sqlite3_open_v2(fixture.path, &raw, SQLITE_OPEN_READONLY, nil) == SQLITE_OK)
        let db = try #require(raw)
        defer { sqlite3_close(db) }
        return try scalar("""
            SELECT COUNT(*) FROM sqlite_master
            WHERE name = 'idx_events_timestamp' AND type = 'view'
            """, on: db) == 1
    }

    private func execute(_ sql: String, on db: OpaquePointer) throws {
        let rc = sqlite3_exec(db, sql, nil, nil, nil)
        guard rc == SQLITE_OK else {
            throw NSError(domain: "LegacyUpgradeFixture", code: Int(rc), userInfo: [
                NSLocalizedDescriptionKey: String(cString: sqlite3_errmsg(db)),
            ])
        }
    }

    private struct RecoveryBoundary: Sendable, Equatable {
        let source: Int64
        let migrated: Int64
        let expired: Int64
        let corrupt: Int64
        let remaining: Int64
        let stage: Int64
        let finalized: Int64
        let reopenEpochs: Int64
        let updatedAt: Double
        let legacyRows: Int64
        let journalBlocks: Int64
        let mutationGeneration: Int64

        var conserved: Bool {
            source == migrated + expired + corrupt + remaining
        }

        var isCommittedMixedState: Bool {
            stage == 1 && migrated > 0 && remaining > 0
                && journalBlocks > 0 && legacyRows == remaining && conserved
        }
    }

    /// A separate read-only connection sees committed recovery progress even
    /// when the owning actor is currently probing inside BEGIN IMMEDIATE.
    private static func committedRecoveryBoundary(at path: String) throws
        -> RecoveryBoundary? {
        var raw: OpaquePointer?
        let openRC = sqlite3_open_v2(
            path, &raw, SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX, nil
        )
        guard openRC == SQLITE_OK, let db = raw else {
            if let raw { sqlite3_close(raw) }
            throw NSError(domain: "LegacyRecoveryBoundary", code: Int(openRC))
        }
        defer { sqlite3_close(db) }
        var query: OpaquePointer?
        let sql = """
            SELECT source_events, migrated_events, rolled_expired_events,
                   corrupt_preserved_events, remaining_events, stage,
                   schema_finalized, reopen_epochs, updated_at,
                   (SELECT COUNT(*) FROM events
                    WHERE journal_block_id IS NULL
                      AND journal_quarantine_marker IS NULL),
                   (SELECT COUNT(*) FROM event_journal_blocks),
                   (SELECT mutation_generation FROM event_storage_state
                    WHERE singleton = 1)
            FROM event_journal_migration WHERE singleton = 1
            """
        let prepareRC = sqlite3_prepare_v2(db, sql, -1, &query, nil)
        guard prepareRC == SQLITE_OK, let query else {
            sqlite3_finalize(query)
            throw NSError(domain: "LegacyRecoveryBoundary", code: Int(prepareRC))
        }
        defer { sqlite3_finalize(query) }
        let stepRC = sqlite3_step(query)
        if stepRC == SQLITE_DONE { return nil }
        guard stepRC == SQLITE_ROW else {
            throw NSError(domain: "LegacyRecoveryBoundary", code: Int(stepRC))
        }
        return RecoveryBoundary(
            source: sqlite3_column_int64(query, 0),
            migrated: sqlite3_column_int64(query, 1),
            expired: sqlite3_column_int64(query, 2),
            corrupt: sqlite3_column_int64(query, 3),
            remaining: sqlite3_column_int64(query, 4),
            stage: sqlite3_column_int64(query, 5),
            finalized: sqlite3_column_int64(query, 6),
            reopenEpochs: sqlite3_column_int64(query, 7),
            updatedAt: sqlite3_column_double(query, 8),
            legacyRows: sqlite3_column_int64(query, 9),
            journalBlocks: sqlite3_column_int64(query, 10),
            mutationGeneration: sqlite3_column_int64(query, 11)
        )
    }

    private final class PressureAfterCommittedMigration: @unchecked Sendable {
        private let lock = NSLock()
        private var interruptedBoundary: RecoveryBoundary?

        func readFreeSpace(volumePath: String, databasePath: String) throws -> Int64 {
            lock.lock()
            defer { lock.unlock() }
            if interruptedBoundary != nil { return 0 }
            if let boundary = try EventStoreLegacyUpgradeTests
                .committedRecoveryBoundary(at: databasePath),
               boundary.isCommittedMixedState {
                interruptedBoundary = boundary
                return 0
            }
            return try SQLitePersistentStoreAdmission.measureFreeSpace(volumePath)
        }

        func observedBoundary() -> RecoveryBoundary? {
            lock.lock()
            defer { lock.unlock() }
            return interruptedBoundary
        }
    }

    private func originalEvents(in fixture: Fixture) throws -> [UUID: Event] {
        var raw: OpaquePointer?
        try #require(sqlite3_open_v2(
            fixture.path, &raw, SQLITE_OPEN_READONLY, nil
        ) == SQLITE_OK)
        let db = try #require(raw)
        defer { sqlite3_close(db) }
        var query: OpaquePointer?
        try #require(sqlite3_prepare_v2(
            db, "SELECT raw_json FROM events", -1, &query, nil
        ) == SQLITE_OK)
        let statement = try #require(query)
        defer { sqlite3_finalize(statement) }
        var result: [UUID: Event] = [:]
        while true {
            let rc = sqlite3_step(statement)
            if rc == SQLITE_DONE { break }
            try #require(rc == SQLITE_ROW)
            let bytes = try #require(sqlite3_column_blob(statement, 0))
            let json = Data(bytes: bytes, count: Int(sqlite3_column_bytes(statement, 0)))
            let event = try JSONDecoder().decode(Event.self, from: json)
            try #require(result.updateValue(event, forKey: event.id) == nil)
        }
        return result
    }

    private func expectExactEvents(
        in store: EventStore,
        originals: [UUID: Event]
    ) async throws {
        // Each bounded query decodes a block once. Querying every UUID alone
        // repeatedly decodes the same wide legacy payloads after migration.
        let sorted = originals.values.sorted { $0.timestamp > $1.timestamp }
        for start in stride(from: 0, to: sorted.count, by: 64) {
            let expected = Array(sorted[start..<min(start + 64, sorted.count)])
            let first = try #require(expected.first)
            let last = try #require(expected.last)
            let snapshot = try await store.exactEventsSnapshot(
                since: last.timestamp.addingTimeInterval(-0.0004),
                until: first.timestamp.addingTimeInterval(0.0004),
                limit: expected.count + 1
            )
            #expect(snapshot.events == expected)
            #expect(snapshot.poisonRecords.isEmpty)
            #expect(snapshot.corruptLegacyRecords == 0)
            #expect(snapshot.inheritedLegacyLossRecords == 0)
            #expect(snapshot.resourceLimitedRecords == 0)
        }
    }

    @Test("Shipped migration resumes after committed multi-batch progress under default and lowered caps",
          arguments: [false, true])
    func interruptedRecoveryPreservesEveryEvent(loweredCap: Bool) async throws {
        let fixture = try fixture(rows: 1_024, payloadBytes: loweredCap ? 48 * 1_024 : 0)
        defer { try? FileManager.default.removeItem(at: fixture.directory) }
        let policy = loweredCap ? loweredUpgradePolicy(for: fixture) : nil
        if let policy {
            try #require(try SQLitePersistentStoreAdmission.measureFamily(fixture.path)
                > policy.maxFootprintBytes)
        }
        let original = try originalEvents(in: fixture)
        #expect(original.count == 1_024)
        let pressure = PressureAfterCommittedMigration()
        let path = fixture.path

        // The scope releases the first store before reopening. This models an
        // ordinary admission failure after a durable chunk, not a power loss.
        func recoverUntilPressure() async throws -> Int64? {
            let store = try EventStore(
                path: path, storagePolicy: policy,
                allowLegacyUpgradeHeadroom: loweredCap
            )
            let initialCap = (await store.storageAdmissionSnapshot())?.maxFootprintBytes
            try await store.setStorageAdmissionProbesForTesting(
                footprint: { try SQLitePersistentStoreAdmission.measureFamily($0) },
                freeSpace: {
                    try pressure.readFreeSpace(volumePath: $0, databasePath: path)
                }
            )
            do {
                _ = try await store.recoverJournalBeforeProducers()
                Issue.record("Recovery completed without observing injected post-commit pressure")
            } catch let error as SQLitePersistentStoreAdmissionError {
                guard case .lowFreeSpace(let free, _, _, _) = error else {
                    throw error
                }
                #expect(free == 0)
            }
            let connection = try await store.storageAdmissionConnectionStateForTesting()
            #expect(!connection.inTransaction)
            let observed = try #require(pressure.observedBoundary())
            let durable = try #require(try Self.committedRecoveryBoundary(at: path))
            #expect(observed == durable)
            #expect(durable.isCommittedMixedState)
            #expect(durable.source == 1_024)
            #expect(durable.corrupt == 0)
            #expect(durable.expired == 0)
            #expect(durable.finalized == 0)
            #expect(try preservedEvidence(in: fixture) == fixture.evidenceJSON)
            // Exercise both the already-journaled prefix and the still-legacy
            // tail before resuming, using every UUID captured before upgrade.
            try await expectExactEvents(in: store, originals: original)
            #expect(try await store.count() == original.count)
            return initialCap
        }
        let interruptedCap = try await recoverUntilPressure()
        let receiptURL = URL(fileURLWithPath: path + ".legacy-upgrade.json")
        let interruptedReceipt = loweredCap ? try Data(contentsOf: receiptURL) : nil

        let reopened = try EventStore(
            path: path, storagePolicy: policy,
            allowLegacyUpgradeHeadroom: loweredCap
        )
        if let interruptedReceipt {
            #expect((await reopened.storageAdmissionSnapshot())?.maxFootprintBytes == interruptedCap)
            #expect(try Data(contentsOf: receiptURL) == interruptedReceipt)
        }
        let recovery = try await reopened.recoverJournalBeforeProducers()
        if let policy {
            _ = try await reopened.restoreConfiguredStorageAdmissionAfterLegacyUpgrade()
            #expect((await reopened.storageAdmissionSnapshot())?.maxFootprintBytes
                == policy.maxFootprintBytes)
        }
        #expect(recovery.complete)
        #expect(recovery.sourceEvents == original.count)
        #expect(recovery.migratedEvents == original.count)
        #expect(recovery.remainingEvents == 0)
        #expect(recovery.corruptPreservedEvents == 0)
        #expect(recovery.rolledExpiredEvents == 0)
        try await expectExactEvents(in: reopened, originals: original)
        #expect(try await reopened.count() == original.count)
        #expect(try preservedEvidence(in: fixture) == fixture.evidenceJSON)
        let evidence = try await reopened.evidenceFor(alertId: fixture.alertID)
        #expect(evidence.map(\.id) == [fixture.first.id])

        let before = try #require(try Self.committedRecoveryBoundary(at: path))
        #expect(before.conserved)
        #expect(before.stage == 2)
        #expect(before.finalized == 1)
        #expect(before.legacyRows == 0)
        let again = try await reopened.recoverJournalBeforeProducers()
        #expect(again == recovery)
        #expect(try Self.committedRecoveryBoundary(at: path) == before)
    }

    @Test("Shipped schema survives reopen before recovery and preserves exact events")
    func recoverAfterReopen() async throws {
        let fixture = try fixture(rows: 3)
        defer { try? FileManager.default.removeItem(at: fixture.directory) }
        var initial: EventStore? = try EventStore(path: fixture.path)
        #expect(try await initial?.count() == 3)
        #expect(try preservedEvidence(in: fixture) == fixture.evidenceJSON)
        initial = nil
        let store = try EventStore(path: fixture.path)
        let recovery = try await store.recoverJournalBeforeProducers()
        #expect(recovery.complete)
        #expect(recovery.sourceEvents == 3)
        #expect(recovery.migratedEvents == 3)
        #expect(recovery.corruptPreservedEvents == 0)
        #expect(recovery.remainingEvents == 0)
        let evidence = try await store.evidenceFor(alertId: fixture.alertID)
        #expect(evidence.count == 1)
        #expect(evidence.first?.id == fixture.first.id)
        #expect(try preservedEvidence(in: fixture) == fixture.evidenceJSON)
        for event in [fixture.first, fixture.last] {
            let snapshot = try await store.exactEventSnapshot(id: event.id)
            #expect(snapshot.event?.id == event.id)
            #expect(snapshot.event?.process.args == event.process.args)
            #expect(snapshot.event?.timestamp == event.timestamp)
        }
        let reopened = try EventStore(path: fixture.path)
        #expect(try await reopened.recoverJournalBeforeProducers().complete)
        #expect(try await reopened.count() == 3)
        #expect(try preservedEvidence(in: fixture) == fixture.evidenceJSON)
    }

    @Test("Split legacy append uses recovery space without producer settlement reserve")
    func splitRecoveryDoesNotBorrowProducerHeadroom() async throws {
        let fixture = try fixture(rows: 1)
        defer { try? FileManager.default.removeItem(at: fixture.directory) }
        let original = try #require(try originalEvents(in: fixture)[fixture.first.id])
        // The shipped override writer bound user_note without a length cap.
        // A bounded wide note raises the existing shared maintenance high-water
        // while the event itself remains small, valid and without inherited loss.
        // Durable migration-split coverage below must prove this data shape
        // actually takes the split path; its size alone is not that proof.
        let note = String(repeating: "n", count: 15 * 1_048_576)
        do {
            var raw: OpaquePointer?
            try #require(sqlite3_open_v2(
                fixture.path, &raw, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX, nil
            ) == SQLITE_OK)
            let db = try #require(raw)
            defer { sqlite3_close(db) }
            var statement: OpaquePointer?
            try #require(sqlite3_prepare_v2(db, """
                INSERT INTO attribution_overrides (
                    event_id, machine_confidence, user_verdict, user_note,
                    schema_version, created_at, updated_at
                ) VALUES (?1, NULL, 'human', ?2, 1, 0, 0)
                """, -1, &statement, nil) == SQLITE_OK)
            let insert = try #require(statement)
            defer { sqlite3_finalize(insert) }
            let transient = unsafeBitCast(
                OpaquePointer(bitPattern: -1)!, to: sqlite3_destructor_type.self
            )
            sqlite3_bind_text(insert, 1, fixture.first.id.uuidString, -1, transient)
            sqlite3_bind_text(insert, 2, note, -1, transient)
            try #require(sqlite3_step(insert) == SQLITE_DONE)
            try #require(sqlite3_changes(db) == 1)
        }

        let store = try EventStore(path: fixture.path)
        let snapshot = try #require(await store.storageAdmissionSnapshot())
        let cap = try #require(snapshot.maxFootprintBytes)
        let reserve = try #require(snapshot.transactionReserveBytes)
        let floor = try #require(snapshot.freeSpaceFloorBytes)
        #expect(reserve == SQLitePersistentStorePolicy.eventTransactionReserveBytes)
        let modeledFootprint = cap - reserve
        // This models capacity through the existing measurement seam. The
        // actual private database remains small and the hard-cap recovery
        // checks still measure its real family on every transaction boundary.
        try await store.setStorageAdmissionProbesForTesting(
            footprint: { _ in modeledFootprint },
            freeSpace: { _ in Int64.max }
        )
        var producerAdmission = try SQLitePersistentStoreAdmission(
            databasePath: fixture.path,
            policy: SQLitePersistentStorePolicy(
                maxFootprintBytes: cap,
                freeSpaceFloorBytes: floor,
                transactionReserveBytes: reserve,
                storageVolumePath: fixture.directory.path
            ),
            footprintProbe: { _ in modeledFootprint },
            freeSpaceProbe: { _ in Int64.max }
        )
        // At this boundary even the smallest positive append cannot retain
        // the producer's future settlement reserve. A successful split append
        // must therefore use the recovery admission contract.
        do {
            try producerAdmission.admitSerializedWrite(
                estimatedTransactionBytes: 1,
                postCommitHeadroomBytes: reserve,
                maintenance: false
            )
            Issue.record("Producer admission unexpectedly fit a positive write plus settlement reserve")
        } catch let error as SQLitePersistentStoreAdmissionError {
            #expect(error == .footprintLimit(
                footprintBytes: modeledFootprint,
                reserveBytes: reserve + 1,
                maxFootprintBytes: cap
            ))
        }

        let recovery = try await store.recoverJournalBeforeProducers()
        #expect(recovery.complete)
        #expect(recovery.sourceEvents == 1)
        #expect(recovery.migratedEvents == 1)
        #expect(recovery.remainingEvents == 0)
        #expect(recovery.corruptPreservedEvents == 0)
        #expect(recovery.rolledExpiredEvents == 0)
        #expect(try await store.exactEventSnapshot(id: original.id).event == original)
        #expect(try await store.count() == 1)
        #expect(try preservedEvidence(in: fixture) == fixture.evidenceJSON)

        var raw: OpaquePointer?
        try #require(sqlite3_open_v2(
            fixture.path, &raw, SQLITE_OPEN_READONLY, nil
        ) == SQLITE_OK)
        let db = try #require(raw)
        defer { sqlite3_close(db) }
        #expect(try scalar("""
            SELECT COUNT(*) FROM event_projection_block_coverage
            WHERE considered_count = 1 AND omitted_migration_count = 1
              AND materialized_count = 0 AND pending_count = 0
            """, on: db) == 1)
        #expect(try scalar("SELECT COUNT(*) FROM event_journal_blocks", on: db) == 1)
        #expect(try scalar("SELECT COUNT(*) FROM event_journal_inherited_loss", on: db) == 0)
        #expect(try scalar("SELECT COUNT(*) FROM event_journal_legacy_quarantine", on: db) == 0)
        #expect(try scalar("SELECT COUNT(*) FROM event_journal_payload_poison", on: db) == 0)
        var statement: OpaquePointer?
        try #require(sqlite3_prepare_v2(
            db, "SELECT user_note FROM attribution_overrides", -1, &statement, nil
        ) == SQLITE_OK)
        let query = try #require(statement)
        defer { sqlite3_finalize(query) }
        try #require(sqlite3_step(query) == SQLITE_ROW)
        let bytes = try #require(sqlite3_column_blob(query, 0))
        #expect(Data(bytes: bytes, count: Int(sqlite3_column_bytes(query, 0))) == Data(note.utf8))
        #expect(sqlite3_step(query) == SQLITE_DONE)
    }

    @Test("Published v7 upgrade finalizes without rebuilding an unused legacy index",
          arguments: [80, 48])
    func indexFinalizationAfterLegacyTranscode(capMiB: Int64) async throws {
        let fixture = try fixture(rows: 4, incrementalVacuum: true)
        defer { try? FileManager.default.removeItem(at: fixture.directory) }
        let mib: Int64 = 1_048_576
        var originals: [Event] = []
        do {
            var raw: OpaquePointer?
            try #require(sqlite3_open(fixture.path, &raw) == SQLITE_OK)
            let db = try #require(raw)
            defer { sqlite3_close(db) }
            var query: OpaquePointer?
            try #require(sqlite3_prepare_v2(db, "SELECT raw_json FROM events ORDER BY id", -1, &query, nil) == SQLITE_OK)
            let snapshot = try #require(query)
            defer { sqlite3_finalize(snapshot) }
            while true {
                let step = sqlite3_step(snapshot)
                if step == SQLITE_DONE { break }
                try #require(step == SQLITE_ROW)
                let bytes = try #require(sqlite3_column_blob(snapshot, 0))
                originals.append(try JSONDecoder().decode(Event.self, from: Data(
                    bytes: bytes, count: Int(sqlite3_column_bytes(snapshot, 0))
                )))
            }
            try #require(originals.count == 4)

            // Model published retention: valid bounded old Events are inserted
            // and later deleted, leaving reusable pages in a mode-2 file.
            // File padding and artificial ballast tables would not prove this
            // actual legacy-index/migration interaction.
            var statement: OpaquePointer?
            try #require(sqlite3_prepare_v2(db, """
                INSERT INTO events(id,timestamp,event_category,event_type,event_action,severity,
                    process_pid,process_name,process_path,process_commandline,process_ppid,raw_json)
                VALUES(?1,?2,'process','start','exec','informational',4242,'true','/usr/bin/true','/usr/bin/true',1,?3)
                """, -1, &statement, nil) == SQLITE_OK)
            let insert = try #require(statement)
            defer { sqlite3_finalize(insert) }
            let transient = unsafeBitCast(OpaquePointer(bitPattern: -1)!, to: sqlite3_destructor_type.self)
            let payload = String(repeating: "retained-fixture-", count: 3_000)
            var retired = 0
            while try scalar("PRAGMA page_count", on: db) * fixture.pageSizeBytes < 32 * mib {
                try #require(retired < 1_024)
                try execute("BEGIN IMMEDIATE", on: db)
                for _ in 0..<32 {
                    var event = Event(
                        timestamp: fixture.last.timestamp.addingTimeInterval(-86_400 - Double(retired)),
                        eventCategory: .process, eventType: .start, eventAction: "exec", process: fixture.first.process
                    )
                    event.enrichments["retired_fixture_detail"] = payload
                    let json = try JSONEncoder().encode(event)
                    try #require(json.count <= 65_536)
                    sqlite3_reset(insert)
                    sqlite3_clear_bindings(insert)
                    sqlite3_bind_text(insert, 1, event.id.uuidString, -1, transient)
                    sqlite3_bind_double(insert, 2, event.timestamp.timeIntervalSince1970)
                    sqlite3_bind_text(insert, 3, String(decoding: json, as: UTF8.self), -1, transient)
                    try #require(sqlite3_step(insert) == SQLITE_DONE)
                    retired += 1
                }
                try execute("COMMIT", on: db)
            }
            try execute("BEGIN IMMEDIATE", on: db)
            try execute("DELETE FROM events_fts WHERE rowid IN (SELECT rowid FROM events ORDER BY timestamp ASC LIMIT \(retired))", on: db)
            try execute("DELETE FROM events WHERE rowid IN (SELECT rowid FROM events ORDER BY timestamp ASC LIMIT \(retired))", on: db)
            #expect(Int(sqlite3_changes(db)) == retired)
            try execute("COMMIT", on: db)
            var logged: Int32 = 0
            var checkpointed: Int32 = 0
            try #require(sqlite3_wal_checkpoint_v2(db, nil, SQLITE_CHECKPOINT_TRUNCATE, &logged, &checkpointed) == SQLITE_OK)
            try #require(logged == checkpointed)
            try #require(try scalar("PRAGMA user_version", on: db) == 6)
            try #require(try scalar("PRAGMA auto_vacuum", on: db) == 2)
            try #require(try scalar("PRAGMA freelist_count", on: db) * fixture.pageSizeBytes > 30 * mib)
            try #require(try scalar("SELECT COUNT(*) FROM events", on: db) == 4)
        }
        let policy = SQLitePersistentStorePolicy(
            maxFootprintBytes: capMiB * mib,
            freeSpaceFloorBytes: SQLitePersistentStorePolicy.freeSpaceFloorBytes,
            transactionReserveBytes: SQLitePersistentStorePolicy.eventTransactionReserveBytes,
            storageVolumePath: fixture.directory.path
        )
        let family = try SQLitePersistentStoreAdmission.measureFamily(fixture.path)
        let main = try SQLitePersistentStoreAdmission.measureMainFile(fixture.path)
        if capMiB == 80 {
            try #require(family + policy.transactionReserveBytes < policy.maxFootprintBytes)
        } else {
            // The smaller envelope also requires the real pre-open reclaim
            // path. It cannot leave two reserves even after every free page
            // is reclaimed, so sufficient ordinary headroom must let it finish.
            try #require(family < policy.maxFootprintBytes)
            try #require(family + policy.transactionReserveBytes > policy.maxFootprintBytes)
        }
        try #require(family + 3 * main > policy.maxFootprintBytes)
        let store = try EventStore(path: fixture.path, storagePolicy: policy)
        let recovered = try await store.recoverJournalBeforeProducers()
        #expect(recovered.complete && recovered.sourceEvents == 4 && recovered.migratedEvents == 4)
        #expect(try SQLitePersistentStoreAdmission.measureFamily(fixture.path)
            + policy.transactionReserveBytes <= policy.maxFootprintBytes)
        #expect(recovered.remainingEvents == 0 && recovered.corruptPreservedEvents == 0 && recovered.rolledExpiredEvents == 0)
        for event in originals {
            #expect(try await store.exactEventSnapshot(id: event.id).event == event)
        }
        #expect(try preservedEvidence(in: fixture) == fixture.evidenceJSON)
        do {
            var raw: OpaquePointer?
            try #require(sqlite3_open_v2(fixture.path, &raw, SQLITE_OPEN_READONLY, nil) == SQLITE_OK)
            let db = try #require(raw)
            defer { sqlite3_close(db) }
            #expect(try scalar("SELECT schema_finalized FROM event_journal_migration WHERE singleton=1", on: db) == 1)
            #expect(try scalar("SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name IN ('idx_events_process_path','idx_events_ts_severity')", on: db) == 0)
            #expect(try scalar("SELECT COUNT(*) FROM sqlite_master WHERE name='idx_events_cat_sev_ts'", on: db) == 0)
            #expect(try scalar("SELECT COUNT(*) FROM event_journal_payload_poison", on: db) == 0)
            #expect(try scalar("SELECT COUNT(*) FROM event_journal_inherited_loss", on: db) == 0)
        }
        #expect(try await store.recoverJournalBeforeProducers() == recovered)
        let reopened = try EventStore(path: fixture.path, storagePolicy: policy)
        #expect(try await reopened.recoverJournalBeforeProducers() == recovered)
        for event in originals {
            #expect(try await reopened.exactEventSnapshot(id: event.id).event == event)
        }
        #expect(try preservedEvidence(in: fixture) == fixture.evidenceJSON)
        do {
            let filtered = try await reopened.exactEventsSnapshot(
                since: fixture.last.timestamp.addingTimeInterval(-1),
                category: .process, severity: .informational, limit: 10
            )
            #expect(filtered.events.sorted { $0.id.uuidString < $1.id.uuidString } == originals)
            #expect(try await reopened.retainedWindowSecondsByCategory()["process"] != nil)
        }
        // Earlier candidates and fresh stores can retain this optional index.
        // Its presence must also preserve the finalized, idempotent reopen.
        do {
            var raw: OpaquePointer?
            try #require(sqlite3_open(fixture.path, &raw) == SQLITE_OK)
            let db = try #require(raw)
            defer { sqlite3_close(db) }
            try execute("CREATE INDEX idx_events_cat_sev_ts ON events(event_category,severity,timestamp)", on: db)
        }
        let withOptionalIndex = try EventStore(path: fixture.path, storagePolicy: policy)
        #expect(try await withOptionalIndex.recoverJournalBeforeProducers() == recovered)
        for event in originals {
            #expect(try await withOptionalIndex.exactEventSnapshot(id: event.id).event == event)
        }
    }

    @Test("A legacy index uses available schema space independently of row-write reserve",
          arguments: [50_000, 1_500_000])
    func independentlySizedSchemaWork(rows: Int) async throws {
        let fixture = try fixture(rows: rows)
        defer { try? FileManager.default.removeItem(at: fixture.directory) }
        // The large corpus crosses the actual production 32 MiB reserve.
        // Its explicit family cap models an operator retaining a larger store;
        // the ordinary default cap does not promise to hold 1.5M full events.
        let largeCorpus = rows > 50_000
        let policy = SQLitePersistentStorePolicy(
            maxFootprintBytes: (largeCorpus ? 8_192 : 512) * 1_048_576,
            freeSpaceFloorBytes: SQLitePersistentStorePolicy.freeSpaceFloorBytes,
            transactionReserveBytes: largeCorpus
                ? SQLitePersistentStorePolicy.eventTransactionReserveBytes
                : 4 * 1_048_576,
            storageVolumePath: fixture.directory.path
        )
        // This shipped schema has 12 missing write guards and one barrier view.
        // Verify the fixture actually requires more than its ordinary reserve;
        // otherwise a smaller index after fixture changes could mask regression.
        let barrierEstimate = SQLitePersistentStoreAdmission.conservativeTransactionBytes(
            rowMutationBytes: fixture.timestampIndexBytes * 2
                + 13 * SQLitePersistentStoreAdmission.conservativeRowMutationBytes,
            pageSizeBytes: fixture.pageSizeBytes,
            maximumTreePathPageTouches: 20
        )
        #expect(barrierEstimate > policy.transactionReserveBytes)
        print("Legacy upgrade fixture rows=\(rows) timestamp_index_bytes=\(fixture.timestampIndexBytes) schema_estimate_bytes=\(barrierEstimate) row_reserve_bytes=\(policy.transactionReserveBytes)")
        let store = try EventStore(path: fixture.path, storagePolicy: policy)
        #expect(try hasInstalledBarrier(in: fixture))
        // This scale assertion measures schema transition and row preservation.
        // count() deliberately decodes/sanitizes the entire legacy corpus; its
        // evidence semantics are covered by the smaller case and recovery test.
        if largeCorpus {
            #expect(try await store.maintenanceRetainedRecordCount() == rows)
        } else {
            #expect(try await store.count() == rows)
        }
        let first = try await store.exactEventSnapshot(id: fixture.first.id)
        #expect(first.event?.id == fixture.first.id)
        #expect(first.event?.timestamp == fixture.first.timestamp)
        #expect(first.event?.process.args == fixture.first.process.args)
        let reopened = try EventStore(path: fixture.path, storagePolicy: policy)
        #expect(try hasInstalledBarrier(in: fixture))
        if largeCorpus {
            #expect(try await reopened.maintenanceRetainedRecordCount() == rows)
        } else {
            #expect(try await reopened.count() == rows)
        }
        #expect(try preservedEvidence(in: fixture) == fixture.evidenceJSON)
    }

    private func loweredUpgradePolicy(
        for fixture: Fixture,
        capMiB: Int64 = 36
    ) -> SQLitePersistentStorePolicy {
        SQLitePersistentStorePolicy(
            maxFootprintBytes: capMiB * 1_048_576,
            freeSpaceFloorBytes: SQLitePersistentStorePolicy.freeSpaceFloorBytes,
            transactionReserveBytes: SQLitePersistentStorePolicy.eventTransactionReserveBytes,
            storageVolumePath: fixture.directory.path
        )
    }

    @Test("A lowered cap admits a legacy upgrade, preserves every event, and remains authoritative after restart")
    func legacyUpgradeAdmittedOverLoweredCap() async throws {
        // Use real bounded Event payloads and the production transaction
        // reserve. An almost-empty store with a tiny artificial reserve also
        // fails on unrelated schema estimates and does not model this upgrade.
        let fixture = try fixture(rows: 2_400, payloadBytes: 48 * 1_024)
        defer { try? FileManager.default.removeItem(at: fixture.directory) }
        let originals = try originalEvents(in: fixture)
        try #require(originals.count == 2_400)
        let family = try SQLitePersistentStoreAdmission.measureFamily(fixture.path)
        let policy = loweredUpgradePolicy(for: fixture, capMiB: 112)
        try #require(policy.transactionReserveBytes < policy.maxFootprintBytes)
        try #require(family > policy.maxFootprintBytes)

        // A temporary preference overage must never waive physical disk
        // safety. This deterministic floor cannot be satisfied on the host.
        let unavailableDisk = SQLitePersistentStorePolicy(
            maxFootprintBytes: policy.maxFootprintBytes,
            freeSpaceFloorBytes: Int64.max / 2,
            transactionReserveBytes: policy.transactionReserveBytes,
            storageVolumePath: policy.storageVolumePath
        )
        do {
            _ = try EventStore(
                path: fixture.path, storagePolicy: unavailableDisk,
                allowLegacyUpgradeHeadroom: true
            )
            Issue.record("Legacy transition bypassed the configured free-space floor")
        } catch let error as SQLitePersistentStoreAdmissionError {
            guard case .lowFreeSpace = error else { throw error }
        }
        #expect(try originalEvents(in: fixture) == originals)
        #expect(try preservedEvidence(in: fixture) == fixture.evidenceJSON)

        // Release the writer before reopening so this also exercises process
        // restart, not merely a second connection to the first writer's WAL.
        func performUpgrade() async throws -> (
            recovery: EventStore.EventJournalRecoverySnapshot,
            cap: Int64,
            receipt: Data
        ) {
            let store = try EventStore(
                path: fixture.path, storagePolicy: policy,
                allowLegacyUpgradeHeadroom: true
            )
            let admission = try #require(await store.storageAdmissionSnapshot())
            let transitionCap = try #require(admission.maxFootprintBytes)
            #expect(transitionCap > policy.maxFootprintBytes)
            let receipt = try Data(contentsOf: URL(fileURLWithPath: fixture.path + ".legacy-upgrade.json"))
            let recovered = try await store.recoverJournalBeforeProducers()
            #expect((await store.storageAdmissionSnapshot())?.maxFootprintBytes == transitionCap)
            #expect(admission.transactionReserveBytes == policy.transactionReserveBytes)
            #expect(admission.freeSpaceFloorBytes == policy.freeSpaceFloorBytes)
            try await expectExactEvents(in: store, originals: originals)
            #expect(try await store.count() == originals.count)
            #expect(try preservedEvidence(in: fixture) == fixture.evidenceJSON)
            return (recovered, transitionCap, receipt)
        }
        let firstBoot = try await performUpgrade()
        let recovered = firstBoot.recovery
        #expect(recovered.complete)
        #expect(recovered.sourceEvents == originals.count)
        #expect(recovered.migratedEvents == originals.count)
        #expect(recovered.remainingEvents == 0)
        #expect(recovered.rolledExpiredEvents == 0)
        #expect(recovered.corruptPreservedEvents == 0)
        let boundary = try #require(try Self.committedRecoveryBoundary(at: fixture.path))
        #expect(boundary.conserved && boundary.finalized == 1)

        let reopened = try EventStore(
            path: fixture.path, storagePolicy: policy,
            allowLegacyUpgradeHeadroom: true
        )
        #expect((await reopened.storageAdmissionSnapshot())?.maxFootprintBytes == firstBoot.cap)
        #expect(try Data(contentsOf: URL(fileURLWithPath: fixture.path + ".legacy-upgrade.json"))
            == firstBoot.receipt)
        #expect(try await reopened.recoverJournalBeforeProducers() == recovered)
        #expect(try Self.committedRecoveryBoundary(at: fixture.path) == boundary)
        #expect(try await reopened.expireJournalBlocks() == 0)
        let readiness = await recoverEventStoreBeforeProducers(
            eventStore: reopened,
            dbPath: fixture.path,
            boundary: EventsSizeCapBoundary(maxSizeMiB: 112),
            processFloorMinutes: 15,
            retentionBudgetHealth: EventRetentionBudgetHealth()
        )
        #expect(readiness.writableBeforeProducers, "\(readiness)")
        let admission = try #require(await reopened.storageAdmissionSnapshot())
        #expect(admission.maxFootprintBytes == policy.maxFootprintBytes)
        #expect(admission.transactionReserveBytes == policy.transactionReserveBytes)
        #expect(admission.freeSpaceFloorBytes == policy.freeSpaceFloorBytes)
        #expect(admission.latchedFailure == nil)
        try await expectExactEvents(in: reopened, originals: originals)
        #expect(try preservedEvidence(in: fixture) == fixture.evidenceJSON)
        let finalReopen = try EventStore(
            path: fixture.path, storagePolicy: policy,
            allowLegacyUpgradeHeadroom: true
        )
        #expect((await finalReopen.storageAdmissionSnapshot())?.maxFootprintBytes
            == policy.maxFootprintBytes)
        #expect(try await finalReopen.recoverJournalBeforeProducers() == recovered)
        #expect(try await finalReopen.count() == originals.count)
    }

    private final class RecoveryProgress: @unchecked Sendable {
        private let lock = NSLock()
        private var reports: [EventStore.EventJournalRecoverySnapshot] = []

        func record(_ report: EventStore.EventJournalRecoverySnapshot) {
            lock.lock()
            defer { lock.unlock() }
            reports.append(report)
        }

        func snapshots() -> [EventStore.EventJournalRecoverySnapshot] {
            lock.lock()
            defer { lock.unlock() }
            return reports
        }
    }

    @Test("Migration progress conserves durable rows and reports completion on migration and reopen")
    func migrationProgressReportsDurableCompletion() async throws {
        let fixture = try fixture(rows: 300)
        defer { try? FileManager.default.removeItem(at: fixture.directory) }
        let store = try EventStore(path: fixture.path)
        let progress = RecoveryProgress()
        let path = fixture.path
        let recovered = try await store.recoverJournalBeforeProducers { report in
            progress.record(report)
            do {
                let durable = try #require(try Self.committedRecoveryBoundary(at: path))
                #expect(durable.source == report.sourceEvents)
                #expect(durable.migrated == report.migratedEvents)
                #expect(durable.remaining == report.remainingEvents)
                #expect(durable.corrupt == report.corruptPreservedEvents)
                #expect(durable.expired == report.rolledExpiredEvents)
                #expect(durable.conserved)
            } catch {
                Issue.record(error)
            }
        }
        let reports = progress.snapshots()
        try #require(reports.count > 1)
        #expect(reports.last == recovered)
        #expect(reports.last?.complete == true)
        #expect(reports.contains { $0.migratedEvents > 0 && $0.remainingEvents > 0 })
        for report in reports {
            #expect(report.sourceEvents == 300)
            #expect(report.sourceEvents == report.migratedEvents + report.remainingEvents
                + report.rolledExpiredEvents + report.corruptPreservedEvents)
        }
        for (previous, next) in zip(reports, reports.dropFirst()) {
            #expect(previous.migratedEvents <= next.migratedEvents)
            #expect(previous.remainingEvents >= next.remainingEvents)
        }
        let boundary = try Self.committedRecoveryBoundary(at: fixture.path)
        let reopened = try EventStore(path: fixture.path)
        let reopenProgress = RecoveryProgress()
        #expect(try await reopened.recoverJournalBeforeProducers(progress: reopenProgress.record)
            == recovered)
        #expect(reopenProgress.snapshots().last == recovered)
        #expect(try Self.committedRecoveryBoundary(at: fixture.path) == boundary)
    }
}
