// AlertStoreSchemaV3Tests.swift
// MacCrabCoreTests
//
// v1.12.6 Wave 2B: alerts.db schema v5 promotes attribution fields
// (user_id, user_name, working_directory, ai_tool, parent_executable,
// process_sha256, host_name) from raw_json / cross-DB join to indexed
// columns on the alert row.
//
// (Filename retains the "V3" prefix used in the original task plan so
// the test discovery wildcard `--filter "AlertStore|AlertSink|AlertSchemaV3"`
// picks it up; the suite is named accurately.)

import Testing
import Foundation
import CSQLCipher
@testable import MacCrabCore

@Suite("AlertStore schema v5 — attribution promotion")
struct AlertStoreSchemaV5Tests {

    // MARK: - Helpers

    private func makeTempPath() -> String {
        NSTemporaryDirectory() + "maccrab_schemaV5_\(UUID().uuidString).db"
    }

    private func cleanup(_ path: String) {
        [path, path + "-wal", path + "-shm"].forEach {
            try? FileManager.default.removeItem(atPath: $0)
        }
    }

    /// Open the SQLite DB directly (read-only) to inspect schema details
    /// the AlertStore API doesn't surface.
    private func openRaw(_ path: String) -> OpaquePointer? {
        var raw: OpaquePointer?
        let rc = sqlite3_open_v2(path, &raw, SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX, nil)
        return rc == SQLITE_OK ? raw : nil
    }

    private func columnNames(in db: OpaquePointer, table: String) -> [String] {
        var stmt: OpaquePointer?
        sqlite3_prepare_v2(db, "PRAGMA table_info(\(table))", -1, &stmt, nil)
        defer { sqlite3_finalize(stmt) }
        var names: [String] = []
        while sqlite3_step(stmt) == SQLITE_ROW {
            if let cstr = sqlite3_column_text(stmt, 1) {
                names.append(String(cString: cstr))
            }
        }
        return names
    }

    private func indexNames(in db: OpaquePointer, table: String) -> [String] {
        var stmt: OpaquePointer?
        sqlite3_prepare_v2(db, "PRAGMA index_list(\(table))", -1, &stmt, nil)
        defer { sqlite3_finalize(stmt) }
        var names: [String] = []
        while sqlite3_step(stmt) == SQLITE_ROW {
            if let cstr = sqlite3_column_text(stmt, 1) {
                names.append(String(cString: cstr))
            }
        }
        return names
    }

    /// Build an Event with all attribution fields populated so AlertSink
    /// has something to enrich the alert with.
    private func eventWith(
        userId: UInt32 = 501,
        userName: String = "alice",
        workingDirectory: String = "/Users/alice/proj",
        aiToolEnrichment: String? = "claude_code",
        parentExecutable: String = "/sbin/launchd",
        sha256: String? = "deadbeef00000000000000000000000000000000000000000000000000000000",
        processPath: String = "/usr/bin/curl"
    ) -> Event {
        let hashes = sha256.map { ProcessHashes(sha256: $0) }
        let process = ProcessInfo(
            pid: 1234,
            ppid: 1,
            rpid: 1,
            name: (processPath as NSString).lastPathComponent,
            executable: processPath,
            commandLine: "\(processPath) -sS https://example.com",
            args: [processPath, "-sS", "https://example.com"],
            workingDirectory: workingDirectory,
            userId: userId,
            userName: userName,
            groupId: 20,
            startTime: Date(),
            exitCode: nil,
            codeSignature: nil,
            ancestors: [ProcessAncestor(pid: 1, executable: parentExecutable, name: (parentExecutable as NSString).lastPathComponent)],
            architecture: "arm64",
            isPlatformBinary: false,
            hashes: hashes
        )
        var enrichments: [String: String] = [:]
        if let aiToolEnrichment {
            enrichments["ai_tool"] = aiToolEnrichment
        }
        return Event(
            eventCategory: .process,
            eventType: .creation,
            eventAction: "exec",
            process: process,
            enrichments: enrichments
        )
    }

    private func bareAlert(id: String = UUID().uuidString, ruleId: String = "test.rule") -> Alert {
        Alert(
            id: id,
            ruleId: ruleId,
            ruleTitle: "Test rule",
            severity: .high,
            eventId: UUID().uuidString,
            processPath: "/usr/bin/curl",
            processName: "curl",
            description: "test",
            suppressed: false
        )
    }

    /// Spin up a fresh AlertSink+AlertStore pair on a temp DB.
    private func makeSink() async throws -> (sink: AlertSink, store: AlertStore, path: String) {
        let path = makeTempPath()
        let store = try AlertStore(path: path)
        let dedup = AlertDeduplicator(suppressionWindow: 60)
        let sink = AlertSink(alertStore: store, deduplicator: dedup)
        return (sink, store, path)
    }

    // MARK: - Schema shape

    @Test("Fresh install lands at user_version = 5 with all attribution columns")
    func freshInstallV5() throws {
        let path = makeTempPath()
        defer { cleanup(path) }

        // Opening the store runs migrations + creates indexes.
        _ = try AlertStore(path: path)

        let raw = try #require(openRaw(path))
        defer { sqlite3_close(raw) }

        let columns = Set(columnNames(in: raw, table: "alerts"))
        for required in [
            "user_id", "user_name", "working_directory",
            "ai_tool", "parent_executable", "process_sha256", "host_name",
        ] {
            #expect(columns.contains(required), "missing column \(required)")
        }

        // Pre-existing columns are still there.
        for required in ["id", "timestamp", "rule_id", "campaign_id", "llm_investigation_json"] {
            #expect(columns.contains(required), "regressed column \(required)")
        }

        // PRAGMA user_version reflects v5.
        let version = try #require(try? SchemaMigrator.readVersion(db: raw))
        #expect(version >= 5, "user_version=\(version), expected ≥ 5")
    }

    @Test("v5 indexes created on user_id and (ai_tool, timestamp)")
    func v5Indexes() throws {
        let path = makeTempPath()
        defer { cleanup(path) }
        _ = try AlertStore(path: path)

        let raw = try #require(openRaw(path))
        defer { sqlite3_close(raw) }

        let indexes = Set(indexNames(in: raw, table: "alerts"))
        #expect(indexes.contains("idx_alerts_user_id"))
        #expect(indexes.contains("idx_alerts_ai_tool_ts"))
    }

    // MARK: - Migration semantics

    @Test("v4 → v5 migration preserves existing rows; new columns read as NULL")
    func migrationFromPreV5PreservesRows() async throws {
        let path = makeTempPath()
        defer { cleanup(path) }

        // Hand-roll a v4-shape DB: schema before Wave 2B. We seed one row
        // and bump user_version=4 directly to simulate an existing install.
        do {
            var raw: OpaquePointer?
            sqlite3_open_v2(path, &raw, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nil)
            defer { sqlite3_close(raw) }
            sqlite3_exec(raw,
                """
                CREATE TABLE alerts (
                    id TEXT PRIMARY KEY, timestamp REAL NOT NULL,
                    rule_id TEXT NOT NULL, rule_title TEXT NOT NULL,
                    severity TEXT NOT NULL, event_id TEXT NOT NULL,
                    process_path TEXT, process_name TEXT, description TEXT,
                    mitre_tactics TEXT, mitre_techniques TEXT,
                    suppressed INTEGER DEFAULT 0,
                    llm_investigation_json TEXT,
                    d3fend_techniques TEXT, remediation_hint TEXT,
                    analyst_metadata_json TEXT,
                    campaign_id TEXT
                )
                """, nil, nil, nil)
            sqlite3_exec(raw,
                """
                INSERT INTO alerts (id, timestamp, rule_id, rule_title, severity, event_id,
                                    process_path, process_name, description, suppressed)
                VALUES ('legacy-1', 1700000000.0, 'r1', 'Old Rule', 'high', 'evt-1',
                        '/bin/bash', 'bash', 'pre-v5 alert', 0)
                """, nil, nil, nil)
            sqlite3_exec(raw, "PRAGMA user_version = 4", nil, nil, nil)
        }

        // Re-open via AlertStore — migration should run to v5.
        let store = try AlertStore(path: path)
        let preserved = try await store.alert(id: "legacy-1")
        #expect(preserved != nil)
        #expect(preserved?.ruleId == "r1")
        #expect(preserved?.processName == "bash")

        // New columns are nil on the legacy row.
        #expect(preserved?.userId == nil)
        #expect(preserved?.userName == nil)
        #expect(preserved?.workingDirectory == nil)
        #expect(preserved?.aiTool == nil)
        #expect(preserved?.parentExecutable == nil)
        #expect(preserved?.processSha256 == nil)
        #expect(preserved?.hostName == nil)

        // Version bumped to 5.
        let raw = try #require(openRaw(path))
        defer { sqlite3_close(raw) }
        let version = try #require(try? SchemaMigrator.readVersion(db: raw))
        #expect(version >= 5)
    }

    @Test("Migration is idempotent — re-opening DB preserves user_version (v6)")
    func migrationIdempotent() async throws {
        let path = makeTempPath()
        defer { cleanup(path) }

        // First open: fresh install creates the schema and runs to the latest
        // migration (v6 — triggering_events_json snapshot column).
        _ = try AlertStore(path: path)
        // Second open: reapplies the migration set against an at-or-ahead
        // counter (no version bump). Must not throw.
        _ = try AlertStore(path: path)
        // Third open for good measure.
        _ = try AlertStore(path: path)

        let raw = try #require(openRaw(path))
        defer { sqlite3_close(raw) }
        let version = try #require(try? SchemaMigrator.readVersion(db: raw))
        #expect(version == 6, "version should be exactly 6 after multiple opens, got \(version)")
    }

    @Test("v2-shape DB opens cleanly on v5 binary — forward-compatible migration")
    func v2ToV5Migration() async throws {
        let path = makeTempPath()
        defer { cleanup(path) }

        // Simulate a v2-shape (pre-D3FEND, pre-campaign) DB.
        do {
            var raw: OpaquePointer?
            sqlite3_open_v2(path, &raw, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nil)
            defer { sqlite3_close(raw) }
            sqlite3_exec(raw,
                """
                CREATE TABLE alerts (
                    id TEXT PRIMARY KEY, timestamp REAL NOT NULL,
                    rule_id TEXT NOT NULL, rule_title TEXT NOT NULL,
                    severity TEXT NOT NULL, event_id TEXT NOT NULL,
                    process_path TEXT, process_name TEXT, description TEXT,
                    mitre_tactics TEXT, mitre_techniques TEXT,
                    suppressed INTEGER DEFAULT 0,
                    llm_investigation_json TEXT
                )
                """, nil, nil, nil)
            sqlite3_exec(raw,
                """
                INSERT INTO alerts (id, timestamp, rule_id, rule_title, severity, event_id, suppressed)
                VALUES ('v2-row', 1700000000.0, 'r1', 'Old', 'medium', 'e1', 0)
                """, nil, nil, nil)
            sqlite3_exec(raw, "PRAGMA user_version = 2", nil, nil, nil)
        }

        // Open via current binary — should walk through v3, v4, v5.
        let store = try AlertStore(path: path)
        let row = try await store.alert(id: "v2-row")
        #expect(row != nil)

        let raw = try #require(openRaw(path))
        defer { sqlite3_close(raw) }
        let cols = Set(columnNames(in: raw, table: "alerts"))
        #expect(cols.contains("d3fend_techniques"))   // v3
        #expect(cols.contains("campaign_id"))         // v4
        #expect(cols.contains("ai_tool"))             // v5
    }

    // MARK: - AlertSink event-driven population

    @Test("submit(alert:event:) populates user_id, user_name, working_directory from Event")
    func sinkPopulatesUserFields() async throws {
        let (sink, store, path) = try await makeSink()
        defer { cleanup(path) }

        let alert = bareAlert(id: "a1")
        let event = eventWith(userId: 1337, userName: "bob", workingDirectory: "/Users/bob/work")
        let inserted = try await sink.submit(alert: alert, event: event)
        #expect(inserted == true)

        let row = try await store.alert(id: "a1")
        #expect(row?.userId == 1337)
        #expect(row?.userName == "bob")
        #expect(row?.workingDirectory == "/Users/bob/work")
    }

    @Test("submit() with empty userName stores NULL, not empty string")
    func emptyUserNameStoredAsNull() async throws {
        let (sink, store, path) = try await makeSink()
        defer { cleanup(path) }

        let alert = bareAlert(id: "a2")
        let event = eventWith(userId: 0, userName: "", workingDirectory: "")
        _ = try await sink.submit(alert: alert, event: event)

        let row = try await store.alert(id: "a2")
        // userId=0 IS preserved (root) — UID is numeric, "" semantics
        // don't apply.
        #expect(row?.userId == 0)
        // Empty strings collapse to nil.
        #expect(row?.userName == nil)
        #expect(row?.workingDirectory == nil)

        // Inspect the raw column to confirm it's actually NULL, not ''.
        let raw = try #require(openRaw(path))
        defer { sqlite3_close(raw) }
        var stmt: OpaquePointer?
        sqlite3_prepare_v2(raw, "SELECT user_name, working_directory FROM alerts WHERE id = 'a2'", -1, &stmt, nil)
        defer { sqlite3_finalize(stmt) }
        #expect(sqlite3_step(stmt) == SQLITE_ROW)
        #expect(sqlite3_column_type(stmt, 0) == SQLITE_NULL, "user_name should be SQL NULL, not ''")
        #expect(sqlite3_column_type(stmt, 1) == SQLITE_NULL, "working_directory should be SQL NULL")
    }

    @Test("submit() pulls ai_tool from enrichments['ai_tool']")
    func aiToolFromAiToolKey() async throws {
        let (sink, store, path) = try await makeSink()
        defer { cleanup(path) }

        let alert = bareAlert(id: "a3")
        let event = eventWith(aiToolEnrichment: "claude_code")
        _ = try await sink.submit(alert: alert, event: event)
        let row = try await store.alert(id: "a3")
        #expect(row?.aiTool == "claude_code")
    }

    @Test("submit() falls back to enrichments['agent_tool'] when ai_tool absent")
    func aiToolFallsBackToAgentTool() async throws {
        let (sink, store, path) = try await makeSink()
        defer { cleanup(path) }

        // Build an event without ai_tool but with agent_tool.
        var event = eventWith(aiToolEnrichment: nil)
        event.enrichments["agent_tool"] = "cursor"
        let alert = bareAlert(id: "a4")
        _ = try await sink.submit(alert: alert, event: event)
        let row = try await store.alert(id: "a4")
        #expect(row?.aiTool == "cursor")
    }

    @Test("submit() pulls parent_executable from event.process.ancestors.first")
    func parentExecutableFromAncestor() async throws {
        let (sink, store, path) = try await makeSink()
        defer { cleanup(path) }

        let alert = bareAlert(id: "a5")
        let event = eventWith(parentExecutable: "/Applications/Terminal.app/Contents/MacOS/Terminal")
        _ = try await sink.submit(alert: alert, event: event)
        let row = try await store.alert(id: "a5")
        #expect(row?.parentExecutable == "/Applications/Terminal.app/Contents/MacOS/Terminal")
    }

    @Test("submit() pulls process_sha256 from event.process.hashes.sha256")
    func sha256FromProcessHashes() async throws {
        let (sink, store, path) = try await makeSink()
        defer { cleanup(path) }

        let alert = bareAlert(id: "a6")
        let event = eventWith(sha256: "abc123def456789000000000000000000000000000000000000000000000ffff")
        _ = try await sink.submit(alert: alert, event: event)
        let row = try await store.alert(id: "a6")
        #expect(row?.processSha256 == "abc123def456789000000000000000000000000000000000000000000000ffff")
    }

    @Test("submit() sets host_name from Foundation.ProcessInfo (or fallback)")
    func hostNameAlwaysSet() async throws {
        let (sink, store, path) = try await makeSink()
        defer { cleanup(path) }

        let alert = bareAlert(id: "a7")
        let event = eventWith()
        _ = try await sink.submit(alert: alert, event: event)
        let row = try await store.alert(id: "a7")
        // hostName is non-empty regardless of test environment — either
        // the real hostname or "maccrab-host" fallback.
        #expect(row?.hostName != nil)
        #expect(row?.hostName?.isEmpty == false)
    }

    @Test("submit(alert:) without event still sets host_name")
    func hostNameSetEvenWithoutEvent() async throws {
        let (sink, store, path) = try await makeSink()
        defer { cleanup(path) }

        let alert = bareAlert(id: "a8")
        _ = try await sink.submit(alert: alert)
        let row = try await store.alert(id: "a8")
        #expect(row?.hostName != nil)
        // No event → no user/CWD/aiTool attribution.
        #expect(row?.userId == nil)
        #expect(row?.userName == nil)
        #expect(row?.aiTool == nil)
    }

    @Test("Pre-populated alert attribution fields are preserved over Event-derived ones")
    func explicitFieldsTakePriority() async throws {
        let (sink, store, path) = try await makeSink()
        defer { cleanup(path) }

        // Caller provides aiTool explicitly; the Event also has one.
        // The explicit value wins so callers with richer context aren't
        // overridden by the generic enrichment.
        let alert = Alert(
            id: "a9",
            ruleId: "r",
            ruleTitle: "t",
            severity: .high,
            eventId: "e",
            aiTool: "explicit_tool",
            hostName: "explicit-host"
        )
        let event = eventWith(aiToolEnrichment: "claude_code")
        _ = try await sink.submit(alert: alert, event: event)
        let row = try await store.alert(id: "a9")
        #expect(row?.aiTool == "explicit_tool")
        #expect(row?.hostName == "explicit-host")
    }

    // MARK: - Round-trip

    @Test("Round-trip: a v5 alert with all attribution fields decodes losslessly")
    func roundTripFullAttribution() async throws {
        let (sink, store, path) = try await makeSink()
        defer { cleanup(path) }

        let alert = bareAlert(id: "rt-1")
        let event = eventWith(
            userId: 502,
            userName: "carol",
            workingDirectory: "/Users/carol/code",
            aiToolEnrichment: "cursor",
            parentExecutable: "/bin/zsh",
            sha256: "1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff",
            processPath: "/usr/local/bin/python3"
        )
        _ = try await sink.submit(alert: alert, event: event)

        let row = try await store.alert(id: "rt-1")
        #expect(row?.userId == 502)
        #expect(row?.userName == "carol")
        #expect(row?.workingDirectory == "/Users/carol/code")
        #expect(row?.aiTool == "cursor")
        #expect(row?.parentExecutable == "/bin/zsh")
        #expect(row?.processSha256 == "1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff")
        #expect(row?.hostName != nil)
        // Original Alert fields survive the trip.
        #expect(row?.ruleId == "test.rule")
        #expect(row?.severity == .high)
        #expect(row?.processName == "curl")
    }

    @Test("insertEngineBatch(alerts:event:) populates attribution for every alert in the batch")
    func engineBatchPropagatesAttribution() async throws {
        let (sink, store, path) = try await makeSink()
        defer { cleanup(path) }

        let event = eventWith(userId: 503, userName: "dave", aiToolEnrichment: "claude_code")
        let alerts = [
            bareAlert(id: "b1", ruleId: "r.a"),
            bareAlert(id: "b2", ruleId: "r.b"),
            bareAlert(id: "b3", ruleId: "r.c"),
        ]
        try await sink.insertEngineBatch(alerts: alerts, event: event)

        for id in ["b1", "b2", "b3"] {
            let row = try await store.alert(id: id)
            #expect(row?.userId == 503, "alert \(id) missing user_id")
            #expect(row?.userName == "dave")
            #expect(row?.aiTool == "claude_code")
            #expect(row?.hostName != nil)
        }
    }

    // MARK: - v6 triggering-event snapshot

    @Test("submit(alert:event:) snapshots the triggering event onto the alert (survives event pruning)")
    func sinkSnapshotsTriggeringEvent() async throws {
        let (sink, store, path) = try await makeSink()
        defer { cleanup(path) }

        let alert = bareAlert(id: "snap1")
        let event = eventWith(userId: 1337, userName: "bob", workingDirectory: "/Users/bob/work")
        _ = try await sink.submit(alert: alert, event: event)

        let row = try await store.alert(id: "snap1")
        let json = try #require(row?.triggeringEventsJson,
                                "triggering_events_json should be populated from the Event")
        // It's a JSON array; the triggering event's id must be inside it so the
        // dashboard can render the originating event even after events.db prunes.
        #expect(json.hasPrefix("["))
        #expect(json.contains(event.id.uuidString),
                "snapshot should contain the triggering event's id")
    }

    @Test("alert built without an Event has a nil triggering-event snapshot")
    func noEventNoSnapshot() async throws {
        let (sink, store, path) = try await makeSink()
        defer { cleanup(path) }

        // The Event-less submit path (self-defense / health stubs).
        _ = try await sink.submit(alert: bareAlert(id: "snap2"))
        let row = try await store.alert(id: "snap2")
        #expect(row?.triggeringEventsJson == nil,
                "no-Event alerts must store NULL, not an empty blob")
    }

    @Test("EventSnapshot.encode caps at maxEvents and stays well-formed JSON")
    func snapshotBoundsEvents() {
        let many = (0..<(EventSnapshot.maxEvents + 5)).map { _ in
            eventWith(userId: 1, userName: "x", workingDirectory: "/tmp")
        }
        let json = EventSnapshot.encode(many)
        let data = (json ?? "").data(using: .utf8) ?? Data()
        let arr = (try? JSONSerialization.jsonObject(with: data)) as? [Any]
        #expect(arr != nil, "snapshot must be a JSON array")
        #expect((arr?.count ?? 0) <= EventSnapshot.maxEvents,
                "snapshot must cap at maxEvents, got \(arr?.count ?? -1)")
    }
}
