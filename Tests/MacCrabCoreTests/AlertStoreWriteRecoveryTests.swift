import Foundation
import Testing
import CSQLCipher
@testable import MacCrabCore

@Suite("Alert write pressure preserves current work")
struct AlertStoreWriteRecoveryTests {
    private let mib: Int64 = 1_048_576
    private enum FixtureError: Error { case sqlite(Int32) }

    private func directory() throws -> URL {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrab-alert-write-recovery-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }

    private func policy(_ directory: URL, cap: Int64) -> SQLitePersistentStorePolicy {
        .init(maxFootprintBytes: cap, freeSpaceFloorBytes: 0,
              transactionReserveBytes: 8 * mib, storageVolumePath: directory.path)
    }

    private func alert(_ id: String) -> Alert {
        Alert(id: id, timestamp: Date(timeIntervalSince1970: 1_700_000_000),
              ruleId: "fixture.write-recovery", ruleTitle: "Write recovery",
              severity: .high, eventId: "event-\(id)",
              description: String(repeating: "a", count: 1024))
    }

    private func open(_ path: String) throws -> OpaquePointer {
        var handle: OpaquePointer?
        let rc = sqlite3_open_v2(path, &handle, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX, nil)
        guard rc == SQLITE_OK, let handle else {
            sqlite3_close(handle)
            throw FixtureError.sqlite(rc)
        }
        return handle
    }

    private func execute(_ db: OpaquePointer, _ sql: String) throws {
        let rc = sqlite3_exec(db, sql, nil, nil, nil)
        guard rc == SQLITE_OK else { throw FixtureError.sqlite(rc) }
    }

    private func scalar(_ db: OpaquePointer, _ sql: String) throws -> Int64 {
        var statement: OpaquePointer?
        let rc = sqlite3_prepare_v2(db, sql, -1, &statement, nil)
        guard rc == SQLITE_OK, let statement else {
            sqlite3_finalize(statement)
            throw FixtureError.sqlite(rc)
        }
        defer { sqlite3_finalize(statement) }
        let step = sqlite3_step(statement)
        guard step == SQLITE_ROW else { throw FixtureError.sqlite(step) }
        return sqlite3_column_int64(statement, 0)
    }

    private func padFreelist(_ db: OpaquePointer, bytes: Int64) throws {
        try execute(db, "CREATE TABLE write_recovery_padding(payload BLOB)")
        try execute(db, "INSERT INTO write_recovery_padding VALUES(zeroblob(\(bytes)))")
        try execute(db, "DROP TABLE write_recovery_padding")
        try execute(db, "PRAGMA wal_checkpoint(TRUNCATE)")
        #expect(try scalar(db, "PRAGMA auto_vacuum") == 2)
        #expect(try scalar(db, "PRAGMA freelist_count") > 0)
    }

    /// A second writer can acquire its lock only when the failed operation
    /// released its own transaction. This checks the actual SQLite connection
    /// state without adding a production inspection or fault-injection hook.
    private func assertWriterUnlocked(_ db: OpaquePointer) throws {
        try execute(db, "PRAGMA busy_timeout=0")
        try execute(db, "BEGIN IMMEDIATE")
        try execute(db, "ROLLBACK")
    }

    @Test("WAL pressure checkpoints before considering completed history")
    func walOnlyRecoveryPreservesRows() async throws {
        let dir = try directory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let path = dir.appendingPathComponent("alerts.db").path
        let budget = EventPipelineLiveMemoryBudget(maximumBytes: EventJournalCodec.maximumWorkspaceBytes)
        let store = try AlertStore(path: path, storagePolicy: policy(dir, cap: 64 * mib), liveMemoryBudget: budget)
        let original = alert("original")
        try await store.insert(alert: original)
        try await store.recordEvidenceContext(.init(alertId: original.id, status: .complete,
            sourceMutationGeneration: 7, poisonRecordCount: 0, corruptRecordCount: 0))
        let writer = try open(path)
        defer { sqlite3_close(writer) }
        try padFreelist(writer, bytes: 6 * mib)
        let base = try SQLitePersistentStoreAdmission.measureFamily(path)
        let cap = base + 8 * mib + 512 * 1024
        _ = try await store.updateStorageAdmission(policy(dir, cap: cap))
        try execute(writer, "PRAGMA wal_autocheckpoint=0")
        try execute(writer, "CREATE TABLE write_recovery_wal(payload BLOB)")
        try execute(writer, "INSERT INTO write_recovery_wal VALUES(zeroblob(1048576))")
        try execute(writer, "DROP TABLE write_recovery_wal")
        let before = try SQLitePersistentStoreAdmission.measureFamily(path)
        let main = try SQLitePersistentStoreAdmission.measureMainFile(path)
        #expect(before + 8 * mib > cap)
        #expect(before + (before - main) <= cap, "The checkpoint must fit the unchanged cap")
        try await store.insert(alert: alert("next"))
        #expect(try await store.count() == 2)
        #expect(try await store.alert(id: original.id) == original)
        #expect(try await store.evidenceContext(alertId: original.id)?.sourceMutationGeneration == 7)
        #expect(try SQLitePersistentStoreAdmission.measureFamily(path) + 8 * mib <= cap)
        #expect(budget.snapshot().currentBytes == 0)
        try assertWriterUnlocked(writer)
    }

    @Test("A pinned reader refuses before retention and the same pending alert retries")
    func pinPreservesAndRetryRecovers() async throws {
        let dir = try directory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let path = dir.appendingPathComponent("alerts.db").path
        let budget = EventPipelineLiveMemoryBudget(maximumBytes: EventJournalCodec.maximumWorkspaceBytes)
        let store = try AlertStore(path: path, storagePolicy: policy(dir, cap: 64 * mib), liveMemoryBudget: budget)
        let original = alert("pending")
        try await store.insert(alert: original)
        let writer = try open(path)
        defer { sqlite3_close(writer) }
        try padFreelist(writer, bytes: 6 * mib)
        let reader = try open(path)
        defer { sqlite3_close(reader) }
        try execute(reader, "BEGIN")
        #expect(try scalar(reader, "SELECT COUNT(*) FROM alerts") == 1)
        try execute(writer, "CREATE TABLE write_recovery_pin(value INTEGER)")
        let before = try SQLitePersistentStoreAdmission.measureFamily(path)
        let cap = before + 4 * mib
        _ = try await store.updateStorageAdmission(policy(dir, cap: cap))
        let incoming = alert("retry")
        await #expect(throws: (any Error).self) { try await store.insert(alert: incoming) }
        #expect(try await store.count() == 1)
        #expect(try await store.alert(id: original.id) == original)
        #expect(try await store.evidenceContext(alertId: original.id)?.status == .pending)
        #expect(budget.snapshot().currentBytes == 0)
        try assertWriterUnlocked(writer)
        try execute(reader, "ROLLBACK")
        try await store.insert(alert: incoming)
        #expect(try await store.alert(id: incoming.id) == incoming)
        #expect(try await store.alert(id: original.id) == original)
        #expect(try SQLitePersistentStoreAdmission.measureFamily(path) + 8 * mib <= cap)
        #expect(budget.snapshot().highWatermarkBytes == EventJournalCodec.maximumWorkspaceBytes)
        #expect(budget.snapshot().currentBytes == 0)
    }

    @Test("Workspace refusal preserves rows and one reservation suffices after release")
    func workspaceReservationIsShared() async throws {
        let dir = try directory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let path = dir.appendingPathComponent("alerts.db").path
        let budget = EventPipelineLiveMemoryBudget(maximumBytes: EventJournalCodec.maximumWorkspaceBytes)
        let store = try AlertStore(path: path, storagePolicy: policy(dir, cap: 64 * mib), liveMemoryBudget: budget)
        let original = alert("owned")
        try await store.insert(alert: original)
        let writer = try open(path)
        defer { sqlite3_close(writer) }
        try padFreelist(writer, bytes: 6 * mib)
        let cap = try SQLitePersistentStoreAdmission.measureFamily(path) + 4 * mib
        _ = try await store.updateStorageAdmission(policy(dir, cap: cap))
        var held = budget.tryAcquire(bytes: 1, owner: .eventStoreWorkspace)
        #expect(held != nil)
        await #expect(throws: (any Error).self) { try await store.suppress(alertId: original.id) }
        #expect(try await store.alert(id: original.id) == original)
        #expect(budget.snapshot().currentBytes == 1)
        try assertWriterUnlocked(writer)
        withExtendedLifetime(held) {}
        held = nil
        try await store.suppress(alertId: original.id)
        #expect(try await store.alert(id: original.id)?.suppressed == true)
        try await store.unsuppress(alertId: original.id)
        #expect(try await store.alert(id: original.id) == original)
        #expect(budget.snapshot().currentBytes == 0)
        #expect(budget.snapshot().highWatermarkBytes == EventJournalCodec.maximumWorkspaceBytes)
    }

    @Test("No eligible history preserves every pending context and rolls back before retry")
    func pendingParentsAreNotRetentionCandidates() async throws {
        let dir = try directory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let path = dir.appendingPathComponent("alerts.db").path
        let budget = EventPipelineLiveMemoryBudget(maximumBytes: EventJournalCodec.maximumWorkspaceBytes)
        let store = try AlertStore(path: path, storagePolicy: policy(dir, cap: 64 * mib), liveMemoryBudget: budget)
        let originals = (0..<8).map { alert("pending-\($0)") }
        for value in originals { try await store.insert(alert: value) }
        let writer = try open(path)
        defer { sqlite3_close(writer) }
        try execute(writer, "PRAGMA wal_checkpoint(TRUNCATE)")
        let before = try SQLitePersistentStoreAdmission.measureFamily(path)
        let cap = before + 8 * mib + 4096
        _ = try await store.updateStorageAdmission(policy(dir, cap: cap))
        let record = AlertEvidenceContextRecord(alertId: originals[0].id, status: .complete,
            sourceMutationGeneration: 19, poisonRecordCount: 0, corruptRecordCount: 0)
        await #expect(throws: (any Error).self) { try await store.recordEvidenceContext(record) }
        #expect(try await store.count() == originals.count)
        for value in originals {
            #expect(try await store.alert(id: value.id) == value)
            #expect(try await store.evidenceContext(alertId: value.id)?.status == .pending)
        }
        #expect(budget.snapshot().currentBytes == 0)
        try assertWriterUnlocked(writer)
        _ = try await store.updateStorageAdmission(policy(dir, cap: 64 * mib))
        try await store.recordEvidenceContext(record)
        #expect(try await store.evidenceContext(alertId: record.alertId) == record)
        try assertWriterUnlocked(writer)
    }
    @Test("An oversized batch row cannot borrow the chunk estimate; committed prefix stays explicit")
    func oversizedBatchRowPreservesPrefix() async throws {
        let dir = try directory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let path = dir.appendingPathComponent("alerts.db").path
        let store = try AlertStore(path: path, storagePolicy: policy(dir, cap: 64 * mib))
        let first = alert("valid-prefix")
        var oversized = alert("oversized")
        oversized.description = String(repeating: "z", count: 5 * 1_048_576)
        let following = alert("unattempted")
        let rowEstimate = try AlertStore.estimatedAlertMutationBytes(oversized, pageSizeBytes: 4096)
        #expect(rowEstimate > 8 * mib)
        do {
            _ = try await store.insert(alerts: [first, oversized, following])
            Issue.record("The oversized row must be refused before its DML")
        } catch let failure as AlertBatchInsertFailure {
            #expect(failure.committedAlerts == [first])
            #expect(failure.uncommittedAlerts == [oversized, following])
            #expect(failure.underlyingError is SQLitePersistentStoreAdmissionError)
        }
        #expect(try await store.count() == 1)
        #expect(try await store.alert(id: first.id) == first)
        #expect(try await store.evidenceContext(alertId: first.id)?.status == .pending)
        #expect(try await store.alert(id: oversized.id) == nil)
        #expect(try await store.evidenceContext(alertId: oversized.id) == nil)
        try await store.insert(alert: following)
        #expect(try await store.count() == 2)
    }

}
