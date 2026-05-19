// StoreReadOnlyTests.swift
// MacCrabCoreTests
//
// v1.12.6 Wave 9A: regression coverage for the VACUUM-blocked-by-
// dashboard fix.
//
// Background: events.db grew to 7.46 GB and tracegraph.db to 11 GB on a
// field-test host despite a 300 MB cap. Root cause via `lsof`:
// MacCrab.app (the dashboard process) held *two* writable file
// descriptors on events.db, so the daemon's VACUUM and
// wal_checkpoint(TRUNCATE) silently failed with SQLITE_BUSY — the
// freelist grew to 93 % of the file and disk never reclaimed.
//
// Fix: each dashboard-side store open now passes `forceReadOnly: true`,
// which skips the RW open + chmod / umask / migration write paths and
// drops the shared/upgrade locks that block VACUUM.
//
// This suite locks the new behaviour down so a future refactor of
// `openDatabase` can't quietly bring back the RW open. Six tests:
//   1. EventStore RO insert throws
//   2. AlertStore RO insert throws
//   3. CampaignStore RO insert throws
//   4. TraceStore (SQLiteCausalGraphStore) RO upsert throws
//   5. Reading from a RO store succeeds (the real dashboard use case)
//   6. RO + RW connections coexist (WAL mode sanity)

import Testing
import Foundation
import CSQLCipher
@testable import MacCrabCore

@Suite("Store read-only mode (v1.12.6 Wave 9A)")
struct StoreReadOnlyTests {

    // MARK: - Helpers

    /// Allocate a fresh, isolated temp directory each test gets its own so
    /// concurrent tests can't collide on the WAL/SHM sidecar files.
    private func makeTempDir() -> URL {
        let dir = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("maccrab-ro-\(UUID().uuidString)")
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }

    private func cleanup(_ dir: URL) {
        try? FileManager.default.removeItem(at: dir)
    }

    /// Build a minimal valid Event for EventStore.insert. All required
    /// fields populated; everything else default.
    private func sampleEvent() -> Event {
        let proc = ProcessInfo(
            pid: 4242, ppid: 1, rpid: 1,
            name: "ro-test",
            executable: "/usr/local/bin/ro-test",
            commandLine: "/usr/local/bin/ro-test",
            args: ["/usr/local/bin/ro-test"],
            workingDirectory: "/",
            userId: 501, userName: "tester", groupId: 20,
            startTime: Date(),
            ancestors: [],
            isPlatformBinary: false
        )
        return Event(
            timestamp: Date(),
            eventCategory: .process,
            eventType: .start,
            eventAction: "exec",
            process: proc
        )
    }

    /// Build a minimal valid Alert for AlertStore.insert.
    private func sampleAlert() -> Alert {
        Alert(
            id: UUID().uuidString,
            timestamp: Date(),
            ruleId: "test.ro",
            ruleTitle: "Read-only smoke test",
            severity: .low,
            eventId: UUID().uuidString,
            processPath: "/usr/local/bin/ro-test",
            processName: "ro-test",
            description: "store read-only regression"
        )
    }

    /// Build a minimal valid CampaignStore.Record.
    private func sampleCampaign(id: String = UUID().uuidString) -> CampaignStore.Record {
        CampaignStore.Record(
            id: id,
            type: "test",
            severity: .low,
            title: "Read-only campaign",
            description: "ro campaign",
            tactics: ["TA0001"],
            timeSpanSeconds: 60,
            detectedAt: Date()
        )
    }

    /// Build a minimal valid TraceEntity for trace store upserts.
    private func sampleEntity(id: String = UUID().uuidString) -> TraceEntity {
        TraceEntity(
            id: id,
            entityType: "process",
            stableKey: id,
            displayName: "ro-test",
            firstSeen: Date(),
            lastSeen: Date(),
            attributesJson: "{}",
            source: "test"
        )
    }

    /// Bootstrap a real DB file by opening RW once, then closing. The
    /// dashboard-side RO open requires the DB to already exist — SQLITE_OPEN_READONLY
    /// doesn't create files.
    private func bootstrapEventsDB(at dir: URL) async throws {
        let writer = try EventStore(directory: dir.path)
        // Drop one row so the schema is real and queries return data.
        try await writer.insert(event: sampleEvent())
        _ = writer // hold across the await
    }

    private func bootstrapAlertsDB(at dir: URL) async throws {
        let writer = try AlertStore(directory: dir.path)
        try await writer.insert(alert: sampleAlert())
        _ = writer
    }

    private func bootstrapCampaignsDB(at dir: URL) async throws {
        let writer = try CampaignStore(directory: dir.path)
        try await writer.insert(sampleCampaign())
        _ = writer
    }

    private func bootstrapTraceDB(at dir: URL) async throws {
        let path = dir.appendingPathComponent("tracegraph.db").path
        let writer = try await SQLiteCausalGraphStore(databasePath: path)
        try await writer.upsertEntity(sampleEntity())
        await writer.close()
    }

    // MARK: - Test 1: EventStore RO insert throws

    @Test("EventStore opens read-only when forceReadOnly=true (insert throws)")
    func eventStoreReadOnlyInsertThrows() async throws {
        let dir = makeTempDir()
        defer { cleanup(dir) }
        try await bootstrapEventsDB(at: dir)

        let ro = try EventStore(directory: dir.path, forceReadOnly: true)
        await #expect(throws: (any Error).self) {
            try await ro.insert(event: sampleEvent())
        }
    }

    // MARK: - Test 2: AlertStore RO insert throws

    @Test("AlertStore opens read-only when forceReadOnly=true (insert throws)")
    func alertStoreReadOnlyInsertThrows() async throws {
        let dir = makeTempDir()
        defer { cleanup(dir) }
        try await bootstrapAlertsDB(at: dir)

        let ro = try AlertStore(directory: dir.path, forceReadOnly: true)
        await #expect(throws: (any Error).self) {
            try await ro.insert(alert: sampleAlert())
        }
    }

    // MARK: - Test 3: CampaignStore RO insert throws

    @Test("CampaignStore opens read-only when forceReadOnly=true (insert throws)")
    func campaignStoreReadOnlyInsertThrows() async throws {
        let dir = makeTempDir()
        defer { cleanup(dir) }
        try await bootstrapCampaignsDB(at: dir)

        let ro = try CampaignStore(directory: dir.path, forceReadOnly: true)
        await #expect(throws: (any Error).self) {
            try await ro.insert(sampleCampaign())
        }
    }

    // MARK: - Test 4: TraceStore (SQLiteCausalGraphStore) RO upsert throws

    @Test("SQLiteCausalGraphStore opens read-only when forceReadOnly=true (upsert throws)")
    func traceStoreReadOnlyUpsertThrows() async throws {
        let dir = makeTempDir()
        defer { cleanup(dir) }
        try await bootstrapTraceDB(at: dir)

        let path = dir.appendingPathComponent("tracegraph.db").path
        let ro = try await SQLiteCausalGraphStore(databasePath: path, forceReadOnly: true)
        defer { Task { await ro.close() } }

        await #expect(throws: (any Error).self) {
            try await ro.upsertEntity(sampleEntity())
        }
    }

    // MARK: - Test 5: Reading from a read-only store succeeds

    @Test("Reading from a read-only store succeeds (the dashboard's actual use case)")
    func readOnlyReadsSucceed() async throws {
        let dir = makeTempDir()
        defer { cleanup(dir) }

        // Seed each store with one row via a writer, close, reopen RO.
        try await bootstrapEventsDB(at: dir)
        try await bootstrapAlertsDB(at: dir)
        try await bootstrapCampaignsDB(at: dir)

        let eventRO = try EventStore(directory: dir.path, forceReadOnly: true)
        let alertRO = try AlertStore(directory: dir.path, forceReadOnly: true)
        let campaignRO = try CampaignStore(directory: dir.path, forceReadOnly: true)

        // Each read should observe the seeded row.
        let events = try await eventRO.events(since: .distantPast, limit: 10)
        #expect(events.count == 1)

        let alerts = try await alertRO.alerts(since: .distantPast, limit: 10)
        #expect(alerts.count == 1)

        let campaigns = try await campaignRO.list(includeSuppressed: true, limit: 10)
        #expect(campaigns.count == 1)
    }

    // MARK: - Test 6: RO + RW coexistence under WAL

    @Test("Read-only and read-write connections can coexist on the same DB (WAL sanity)")
    func readOnlyCoexistsWithWriter() async throws {
        let dir = makeTempDir()
        defer { cleanup(dir) }

        // Step 1: open RW, insert one row, keep handle alive.
        let writer = try EventStore(directory: dir.path)
        try await writer.insert(event: sampleEvent())

        // Step 2: open a second connection RO (mirrors dashboard's open
        // shape — separate handle, same DB file).
        let reader = try EventStore(directory: dir.path, forceReadOnly: true)

        // The reader sees the row from step 1.
        let firstRead = try await reader.events(since: .distantPast, limit: 10)
        #expect(firstRead.count == 1)

        // Step 3: writer can keep writing while the reader is open.
        try await writer.insert(event: sampleEvent())

        // The reader picks up the new row on its next query (WAL mode
        // makes committed rows visible to the RO connection).
        let secondRead = try await reader.events(since: .distantPast, limit: 10)
        #expect(secondRead.count == 2)

        // Step 4: the reader still cannot insert.
        await #expect(throws: (any Error).self) {
            try await reader.insert(event: sampleEvent())
        }
    }
}
