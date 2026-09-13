import CSQLCipher
import Foundation
import Testing
@testable import MacCrabCore

private enum ThreatHunterFixtureError: Error {
    case open(String)
    case execute(String)
}

private actor ThreatHunterLLMBackend: LLMBackend {
    let providerName = "ThreatHunterFixture"
    private let response: String

    init(response: String) { self.response = response }

    func isAvailable() async -> Bool { true }

    func complete(
        systemPrompt: String,
        userPrompt: String,
        maxTokens: Int,
        temperature: Double
    ) async -> String? {
        response
    }
}

private func executeFixtureSQL(at path: String, sql: String) throws {
    var database: OpaquePointer?
    guard sqlite3_open_v2(
        path,
        &database,
        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
        nil
    ) == SQLITE_OK, let database else {
        throw ThreatHunterFixtureError.open(path)
    }
    defer { sqlite3_close(database) }

    var errorMessage: UnsafeMutablePointer<CChar>?
    guard sqlite3_exec(database, sql, nil, nil, &errorMessage) == SQLITE_OK else {
        let detail = errorMessage.map { String(cString: $0) } ?? "unknown"
        sqlite3_free(errorMessage)
        throw ThreatHunterFixtureError.execute(detail)
    }
}

private func makeThreatHunterFixture(rowCount: Int = 550) throws -> (
    directory: URL,
    events: String,
    alerts: String
) {
    let directory = URL(fileURLWithPath: NSTemporaryDirectory())
        .appendingPathComponent("maccrab-threat-hunter-\(UUID().uuidString)")
    try FileManager.default.createDirectory(
        at: directory,
        withIntermediateDirectories: true
    )
    let events = directory.appendingPathComponent("events.db").path
    let alerts = directory.appendingPathComponent("alerts.db").path

    try executeFixtureSQL(
        at: events,
        sql: """
        CREATE TABLE events (
            id TEXT PRIMARY KEY,
            timestamp REAL NOT NULL,
            event_category TEXT,
            event_type TEXT,
            event_action TEXT,
            severity TEXT,
            process_name TEXT,
            process_path TEXT,
            process_commandline TEXT,
            process_signer TEXT,
            file_path TEXT,
            network_dest_ip TEXT,
            network_dest_port INTEGER
        );
        WITH RECURSIVE rows(value) AS (
            VALUES(1)
            UNION ALL
            SELECT value + 1 FROM rows WHERE value < \(rowCount)
        )
        INSERT INTO events (
            id, timestamp, event_category, event_type, event_action, severity,
            process_name, process_path, process_commandline, process_signer
        )
        SELECT
            'event-' || value, 1_700_000_000 + value, 'process', 'start',
            'exec', 'informational', 'event-only-marker', '/bin/event-marker',
            'event command ' || value, 'unsigned'
        FROM rows;
        UPDATE events
        SET process_commandline = printf('%020000d', 0)
        WHERE id = 'event-1';
        """
    )
    try executeFixtureSQL(
        at: alerts,
        sql: """
        CREATE TABLE alerts (
            id TEXT PRIMARY KEY,
            timestamp REAL NOT NULL,
            rule_id TEXT,
            rule_title TEXT,
            severity TEXT,
            event_id TEXT,
            process_path TEXT,
            process_name TEXT,
            description TEXT,
            mitre_tactics TEXT,
            mitre_techniques TEXT,
            suppressed INTEGER
        );
        INSERT INTO alerts VALUES (
            'alert-1', 1700000100, 'test.alert', 'alert-only-marker',
            'critical', 'event-1', '/bin/alert-marker', 'alert-marker',
            'separate alert store', 'credential_access', 'T1003', 0
        );
        """
    )
    return (directory, events, alerts)
}

@Suite("ThreatHunter split-store SQL safety")
struct ThreatHunterSQLSafetyTests {
    @Test("LLM hunt SQL validation has conserving accepted and rejected operations")
    func semanticValidationAccounting() async throws {
        let fixture = try makeThreatHunterFixture(rowCount: 2)
        defer { try? FileManager.default.removeItem(at: fixture.directory) }

        let acceptedService = LLMService(
            backend: ThreatHunterLLMBackend(
                response: "SELECT id FROM events ORDER BY timestamp DESC LIMIT 1"
            ),
            config: LLMConfig(),
            minInterval: 0
        )
        let acceptedHunter = ThreatHunter(
            eventsDatabasePath: fixture.events,
            alertsDatabasePath: fixture.alerts,
            llmService: acceptedService
        )
        #expect(await acceptedHunter.huntEnhanced("latest event")?.resultCount == 1)
        let accepted = await acceptedService.runtimeTelemetrySnapshot()
            .counters(for: .threatHunt)?.downstreamValidation
        #expect(accepted?.operationsStartedTotal == 1)
        #expect(accepted?.accepted == 1)
        #expect(accepted?.finalRejection == 0)
        #expect(accepted?.conservationMaintained == true)

        let rejectedService = LLMService(
            backend: ThreatHunterLLMBackend(response: "DELETE FROM events"),
            config: LLMConfig(),
            minInterval: 0
        )
        let rejectedHunter = ThreatHunter(
            eventsDatabasePath: fixture.events,
            alertsDatabasePath: fixture.alerts,
            llmService: rejectedService
        )
        #expect(await rejectedHunter.huntEnhanced("find unsigned processes") != nil,
                "Unsafe LLM SQL must fall back to deterministic hunting")
        let rejected = await rejectedService.runtimeTelemetrySnapshot()
            .counters(for: .threatHunt)?.downstreamValidation
        #expect(rejected?.operationsStartedTotal == 1)
        #expect(rejected?.accepted == 0)
        #expect(rejected?.finalRejection == 1)
        #expect(rejected?.conservationMaintained == true)
    }

    @Test("event and alert queries route to their separate read-only stores")
    func routesSplitStores() async throws {
        let fixture = try makeThreatHunterFixture(rowCount: 2)
        defer { try? FileManager.default.removeItem(at: fixture.directory) }
        let hunter = ThreatHunter(
            eventsDatabasePath: fixture.events,
            alertsDatabasePath: fixture.alerts
        )

        let eventResult = await hunter.executeSQL(
            "SELECT process_name FROM events WHERE id = 'event-1' LIMIT 10"
        )
        #expect(eventResult.status == .completed)
        #expect(eventResult.rows.first?["process_name"] == "event-only-marker")

        let alertResult = await hunter.executeSQL(
            "SELECT rule_title FROM alerts WHERE id = 'alert-1' LIMIT 10"
        )
        #expect(alertResult.status == .completed)
        #expect(alertResult.rows.first?["rule_title"] == "alert-only-marker")

        let eventHunt = await hunter.hunt("find unsigned processes")
        #expect(eventHunt?.status == .completed)
        #expect(eventHunt?.results.first?["process_name"] == "event-only-marker")
        let alertHunt = await hunter.hunt("show critical alerts")
        #expect(alertHunt?.status == .completed)
        #expect(alertHunt?.results.first?["rule_title"] == "alert-only-marker")
    }

    @Test("cross-store, recursive, over-limit, and unsafe-function SQL is rejected")
    func rejectsUnsafeSQL() async throws {
        #expect(
            ThreatHuntSQLPolicy.validate(
                "SELECT * FROM events JOIN alerts ON alerts.event_id = events.id LIMIT 10"
            ) == .rejected(.crossStore)
        )
        #expect(
            ThreatHuntSQLPolicy.validate(
                "SELECT * FROM (WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n) SELECT x FROM n) LIMIT 10"
            ) == .rejected(.recursive)
        )
        #expect(
            ThreatHuntSQLPolicy.validate("SELECT * FROM events LIMIT 501")
                == .rejected(.rowLimitExceeded)
        )

        let fixture = try makeThreatHunterFixture(rowCount: 2)
        defer { try? FileManager.default.removeItem(at: fixture.directory) }
        let hunter = ThreatHunter(
            eventsDatabasePath: fixture.events,
            alertsDatabasePath: fixture.alerts
        )
        let authorizerResult = await hunter.executeSQL(
            "SELECT load_extension('/tmp/not-allowed')"
        )
        #expect(authorizerResult.status == .rejected)

        let excessiveCompound = await hunter.executeSQL(
            """
            SELECT id FROM events
            UNION ALL SELECT id FROM events
            UNION ALL SELECT id FROM events
            UNION ALL SELECT id FROM events
            UNION ALL SELECT id FROM events
            """
        )
        #expect(
            excessiveCompound.status == .rejected,
            "the production connection must enforce its compound-SELECT VM limit"
        )
    }

    @Test("executor enforces row, cell, aggregate, and deadline ceilings")
    func enforcesExecutionCeilings() async throws {
        let fixture = try makeThreatHunterFixture()
        defer { try? FileManager.default.removeItem(at: fixture.directory) }

        let boundedHunter = ThreatHunter(
            eventsDatabasePath: fixture.events,
            alertsDatabasePath: fixture.alerts,
            limits: ThreatHuntExecutionLimits(
                maxRows: 500,
                maxCellBytes: 32,
                maxResultBytes: 128 * 1_024,
                deadlineMilliseconds: 1_000,
                progressSteps: 100
            )
        )
        let rows = await boundedHunter.executeSQL(
            "SELECT id FROM events ORDER BY id"
        )
        #expect(rows.status == .rowLimitReached)
        #expect(rows.rows.count == 500)

        let aggregate = await boundedHunter.executeSQL(
            "SELECT max(process_commandline) AS aggregate_value FROM events LIMIT 1"
        )
        #expect(aggregate.status == .completed)
        #expect((aggregate.rows.first?["aggregate_value"]?.utf8.count ?? 0) <= 32)

        let deadlineHunter = ThreatHunter(
            eventsDatabasePath: fixture.events,
            alertsDatabasePath: fixture.alerts,
            limits: ThreatHuntExecutionLimits(
                deadlineMilliseconds: 1,
                progressSteps: 1
            )
        )
        let timed = await deadlineHunter.executeSQL(
            "SELECT count(*) FROM events a, events b, events c LIMIT 1"
        )
        #expect(timed.status == .timedOut)
    }

    @Test("public hunts preserve store failures and truncation status")
    func publicHuntStatusIsTruthful() async throws {
        let fixture = try makeThreatHunterFixture(rowCount: 20)
        defer { try? FileManager.default.removeItem(at: fixture.directory) }

        try FileManager.default.removeItem(atPath: fixture.alerts)
        let missingAlerts = ThreatHunter(
            eventsDatabasePath: fixture.events,
            alertsDatabasePath: fixture.alerts
        )
        let alertHunt = try #require(
            await missingAlerts.hunt("show critical alerts")
        )
        #expect(alertHunt.status == .databaseUnavailable)
        #expect(alertHunt.results.isEmpty,
                "a failed alert-store query must not widen into event rows")
        #expect(alertHunt.sqlQuery.contains("FROM alerts"))

        let truncated = ThreatHunter(
            eventsDatabasePath: fixture.events,
            alertsDatabasePath: fixture.alerts,
            limits: ThreatHuntExecutionLimits(maxRows: 1)
        )
        let eventHunt = try #require(await truncated.hunt("event"))
        #expect(eventHunt.status == .rowLimitReached)
        #expect(eventHunt.results.count == 1)

        let outputBounded = ThreatHunter(
            eventsDatabasePath: fixture.events,
            alertsDatabasePath: fixture.alerts,
            limits: ThreatHuntExecutionLimits(maxResultBytes: 1)
        )
        let boundedHunt = try #require(await outputBounded.hunt("event"))
        #expect(boundedHunt.status == .resultLimitReached)
        #expect(boundedHunt.results.isEmpty)
    }

    @Test("FTS hunts reject a persisted degraded index while typed hunts survive and verified repair restores FTS")
    func degradedFTSHuntStatus() async throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrab-hunt-fts-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: directory) }
        let path = directory.appendingPathComponent("events.db").path
        let store = try EventStore(path: path)
        _ = try await store.recoverJournalBeforeProducers()
        let now = Date()
        for pid: Int32 in [4242, 4243] {
            _ = try await store.insert(event: Event(
                timestamp: now, eventCategory: .process, eventType: .start,
                eventAction: "exec",
                process: MacCrabCore.ProcessInfo(
                    pid: pid, ppid: 1, rpid: 1, name: "sshprobe",
                    executable: "/usr/bin/sshprobe", commandLine: "sshprobe", args: [],
                    workingDirectory: "/", userId: 501, userName: "fixture", groupId: 20,
                    startTime: now, ancestors: [], isPlatformBinary: false
                )
            ))
        }
        let ftsSQL = "SELECT process_name FROM events_fts WHERE events_fts MATCH 'sshprobe' LIMIT 10"
        let service = LLMService(
            backend: ThreatHunterLLMBackend(response: ftsSQL),
            config: LLMConfig(), minInterval: 0
        )
        let hunter = ThreatHunter(databasePath: path, llmService: service)
        let healthy = await hunter.executeSQL(ftsSQL)
        #expect(healthy.status == .completed)
        #expect(healthy.rows.count == 2)
        for placeholder in ["?", "?1", "?2", ":needle", "@needle", "$needle"] {
            let parameterized = await hunter.executeSQL(
                "SELECT process_name FROM events_fts WHERE events_fts MATCH \(placeholder) LIMIT 10"
            )
            #expect(parameterized.status == .rejected)
            #expect(parameterized.rows.isEmpty)
        }
        #expect(await hunter.executeSQL(
            "SELECT '?1 :needle @needle $needle' AS literal FROM events LIMIT 1"
        ).status == .completed)

        try executeFixtureSQL(at: path, sql:
            "DELETE FROM events_fts WHERE rowid IN (SELECT MIN(rowid) FROM events)")
        try await store.setStorageAdmissionProbesForTesting(
            footprint: { _ in 1_048_576 }, freeSpace: { _ in 16 * 1_048_576 }
        )
        #expect(try await store.recoverJournalBeforeProducers().complete)
        let degraded = await hunter.executeSQL(ftsSQL)
        #expect(degraded.status == .searchIndexDegraded)
        #expect(degraded.rows.isEmpty)
        #expect(await hunter.huntEnhanced("search sshprobe")?.status == .searchIndexDegraded)
        #expect(await hunter.executeSQL(
            "SELECT count(*) FROM events_fts_data LIMIT 1"
        ).status == .searchIndexDegraded)
        let typed = await hunter.executeSQL("SELECT process_name FROM events LIMIT 10")
        #expect(typed.status == .completed)
        #expect(typed.rows.count == 2)
        #expect(await hunter.executeSQL(
            "SELECT 'events_fts' AS label FROM events LIMIT 1"
        ).status == .completed)
        #expect(await hunter.executeSQL("PRAGMA data_version").status == .rejected)
        #expect(await hunter.executeSQL(
            "SELECT name FROM sqlite_schema LIMIT 1"
        ).status == .rejected)

        try await store.setStorageAdmissionProbesForTesting(
            footprint: { try SQLitePersistentStoreAdmission.measureFamily($0) },
            freeSpace: { try SQLitePersistentStoreAdmission.measureFreeSpace($0) }
        )
        #expect(try await store.recoverJournalBeforeProducers().complete)
        let recovered = await hunter.executeSQL(ftsSQL)
        #expect(recovered.status == .completed)
        #expect(recovered.rows.count == 2)
    }

    @Test("LLM hunt prompt matches the production SQL policy")
    func promptPolicyDoesNotDrift() {
        let prompt = LLMPrompts.threatHuntSystem
        #expect(prompt.contains("exactly one store"))
        #expect(prompt.contains("never join events/events_fts with alerts"))
        #expect(prompt.contains("Do not use WITH"))
        #expect(prompt.contains("LIMIT must not exceed 500"))
    }
}
