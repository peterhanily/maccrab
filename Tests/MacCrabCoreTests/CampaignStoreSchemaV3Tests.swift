// CampaignStoreSchemaV3Tests.swift
// MacCrabCore — Wave 2C schema enrichment tests.
//
// Despite the file name (which matches the v1.12.6 Wave 2C task spec
// referring to "schema v3"), the actual on-disk user_version is bumped
// to 2 by this migration because campaigns.db started at v1 — the spec
// was written assuming v2 baseline. Test naming follows the task
// terminology; SQL assertions check the real version values.

import Testing
import Foundation
import SQLite3
@testable import MacCrabCore

@Suite("Campaign Store Schema v2 — Wave 2C aggregates")
struct CampaignStoreSchemaV3Tests {

    // MARK: - Helpers

    private func makeTempPath() -> String {
        NSTemporaryDirectory() + "maccrab_campaign_v2_\(UUID().uuidString).db"
    }

    private func cleanup(_ path: String) {
        for sidecar in ["", "-wal", "-shm", "-journal"] {
            try? FileManager.default.removeItem(atPath: path + sidecar)
        }
    }

    /// Latest known migration version for campaigns.db. Pulled from the
    /// store's own declaration so this test moves with the migration list.
    private var latestSchemaVersion: Int {
        CampaignStore.schemaMigrations.map(\.version).max() ?? 0
    }

    /// Open the campaigns DB raw so we can inspect schema / pragma state
    /// without going through the actor.
    private func openRaw(at path: String) -> OpaquePointer? {
        var raw: OpaquePointer?
        let rc = sqlite3_open_v2(
            path,
            &raw,
            SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX,
            nil
        )
        return rc == SQLITE_OK ? raw : nil
    }

    /// Run `PRAGMA table_info(campaigns)` and return the set of column names.
    private func columnNames(at path: String) -> Set<String> {
        guard let raw = openRaw(at: path) else { return [] }
        defer { sqlite3_close(raw) }
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(raw, "PRAGMA table_info(campaigns)", -1, &stmt, nil) == SQLITE_OK else {
            return []
        }
        defer { sqlite3_finalize(stmt) }
        var names: Set<String> = []
        while sqlite3_step(stmt) == SQLITE_ROW {
            // column index 1 = name
            if let cstr = sqlite3_column_text(stmt, 1) {
                names.insert(String(cString: cstr))
            }
        }
        return names
    }

    /// Build a minimal contributing-alert reference for fixture records.
    private func ref(
        ruleId: String = "r1",
        ruleTitle: String = "Sample alert",
        severity: Severity = .high,
        processPath: String? = nil,
        userId: String? = nil,
        timestamp: Date = Date(),
        tactics: [String] = []
    ) -> CampaignStore.AlertRef {
        CampaignStore.AlertRef(
            ruleId: ruleId,
            ruleTitle: ruleTitle,
            severity: severity,
            processPath: processPath,
            pid: 1234,
            userId: userId,
            timestamp: timestamp,
            tactics: tactics
        )
    }

    // MARK: - 1. Fresh install schema

    @Test("Fresh install lands at latest user_version with all v2 columns")
    func freshInstallSchema() async throws {
        let path = makeTempPath()
        defer { cleanup(path) }

        _ = try CampaignStore(path: path)

        // 1a. user_version is at the latest known migration.
        let raw = try #require(openRaw(at: path))
        defer { sqlite3_close(raw) }
        let version = try SchemaMigrator.readVersion(db: raw)
        #expect(version == latestSchemaVersion)
        #expect(version >= 2)

        // 1b. All v2 aggregate columns are present on a brand-new DB.
        let cols = columnNames(at: path)
        #expect(cols.contains("affected_users"))
        #expect(cols.contains("affected_executables"))
        #expect(cols.contains("first_seen"))
        #expect(cols.contains("last_seen"))
        #expect(cols.contains("process_tree_depth"))
        #expect(cols.contains("techniques"))
        #expect(cols.contains("ai_tools"))
    }

    // MARK: - 2. v1 → v2 migration

    @Test("v1 → v2 migration preserves rows and writes NULL for new columns")
    func migrationFromV1() async throws {
        let path = makeTempPath()
        defer { cleanup(path) }

        // Hand-build a pre-v2 campaigns.db: original 10-column schema,
        // user_version = 1, one row inserted via the v1 INSERT shape.
        var raw: OpaquePointer?
        #expect(sqlite3_open_v2(path, &raw, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX, nil) == SQLITE_OK)
        let handle = try #require(raw)

        let v1Schema = """
            CREATE TABLE campaigns (
                id TEXT PRIMARY KEY,
                detected_at REAL NOT NULL,
                type TEXT NOT NULL,
                severity TEXT NOT NULL,
                title TEXT NOT NULL,
                tactics TEXT NOT NULL,
                time_span_seconds REAL NOT NULL,
                suppressed INTEGER NOT NULL DEFAULT 0,
                notes TEXT,
                raw_json TEXT NOT NULL
            )
            """
        #expect(sqlite3_exec(handle, v1Schema, nil, nil, nil) == SQLITE_OK)
        #expect(sqlite3_exec(handle, "PRAGMA user_version = 1", nil, nil, nil) == SQLITE_OK)

        // Insert a synthetic legacy row. raw_json need only round-trip
        // for CampaignStore.Record's decoder — minimal viable payload.
        let legacyRecord = CampaignStore.Record(
            id: "legacy-1",
            type: "kill_chain",
            severity: .high,
            title: "Legacy campaign",
            description: "Pre-v2 row",
            tactics: ["TA0001", "TA0002"],
            timeSpanSeconds: 42,
            detectedAt: Date(timeIntervalSince1970: 1_700_000_000),
            alerts: []
        )
        let legacyJSON = try JSONEncoder().encode(legacyRecord)
        let legacyJSONString = try #require(String(data: legacyJSON, encoding: .utf8))
        let insertSQL = """
            INSERT INTO campaigns
              (id, detected_at, type, severity, title, tactics, time_span_seconds,
               suppressed, notes, raw_json)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
            """
        var ins: OpaquePointer?
        #expect(sqlite3_prepare_v2(handle, insertSQL, -1, &ins, nil) == SQLITE_OK)
        let insStmt = try #require(ins)
        let SQLITE_TRANSIENT = unsafeBitCast(-1, to: sqlite3_destructor_type.self)
        sqlite3_bind_text(insStmt, 1, "legacy-1", -1, SQLITE_TRANSIENT)
        sqlite3_bind_double(insStmt, 2, legacyRecord.detectedAt.timeIntervalSince1970)
        sqlite3_bind_text(insStmt, 3, "kill_chain", -1, SQLITE_TRANSIENT)
        sqlite3_bind_text(insStmt, 4, "high", -1, SQLITE_TRANSIENT)
        sqlite3_bind_text(insStmt, 5, "Legacy campaign", -1, SQLITE_TRANSIENT)
        sqlite3_bind_text(insStmt, 6, "TA0001,TA0002", -1, SQLITE_TRANSIENT)
        sqlite3_bind_double(insStmt, 7, 42)
        sqlite3_bind_int(insStmt, 8, 0)
        sqlite3_bind_null(insStmt, 9)
        sqlite3_bind_text(insStmt, 10, legacyJSONString, -1, SQLITE_TRANSIENT)
        #expect(sqlite3_step(insStmt) == SQLITE_DONE)
        sqlite3_finalize(insStmt)
        sqlite3_close(handle)

        // Re-open via the store: this should run the v2 migration.
        let store = try CampaignStore(path: path)

        // Schema is now at v2.
        let reopened = try #require(openRaw(at: path))
        defer { sqlite3_close(reopened) }
        let version = try SchemaMigrator.readVersion(db: reopened)
        #expect(version == latestSchemaVersion)

        // All new columns exist.
        let cols = columnNames(at: path)
        #expect(cols.contains("affected_users"))
        #expect(cols.contains("first_seen"))
        #expect(cols.contains("ai_tools"))

        // The legacy row is preserved, and the new columns are NULL on it.
        let fetched = try await store.get(id: "legacy-1")
        #expect(fetched?.id == "legacy-1")
        #expect(fetched?.title == "Legacy campaign")

        // Check the raw column values are NULL via direct SQL.
        var probe: OpaquePointer?
        #expect(sqlite3_prepare_v2(
            reopened,
            "SELECT affected_users, first_seen, process_tree_depth, ai_tools FROM campaigns WHERE id = ?1",
            -1, &probe, nil
        ) == SQLITE_OK)
        let probeStmt = try #require(probe)
        sqlite3_bind_text(probeStmt, 1, "legacy-1", -1, SQLITE_TRANSIENT)
        #expect(sqlite3_step(probeStmt) == SQLITE_ROW)
        #expect(sqlite3_column_type(probeStmt, 0) == SQLITE_NULL)
        #expect(sqlite3_column_type(probeStmt, 1) == SQLITE_NULL)
        #expect(sqlite3_column_type(probeStmt, 2) == SQLITE_NULL)
        #expect(sqlite3_column_type(probeStmt, 3) == SQLITE_NULL)
        sqlite3_finalize(probeStmt)
    }

    // MARK: - 3. Idempotent migration

    @Test("Migration is idempotent across multiple opens")
    func idempotentMigration() async throws {
        let path = makeTempPath()
        defer { cleanup(path) }

        // First open creates fresh-at-latest schema.
        do {
            _ = try CampaignStore(path: path)
        }
        // Subsequent re-opens must not throw or alter the schema.
        for _ in 0..<3 {
            _ = try CampaignStore(path: path)
        }
        let raw = try #require(openRaw(at: path))
        defer { sqlite3_close(raw) }
        let version = try SchemaMigrator.readVersion(db: raw)
        #expect(version == latestSchemaVersion)

        // PRAGMA table_info should still show the v2 columns exactly once
        // (set semantics — duplicates are impossible by SQLite design,
        // but assert anyway as a guard against accidental schema rewrites).
        let cols = columnNames(at: path)
        #expect(cols.contains("affected_users"))
        #expect(cols.contains("ai_tools"))
    }

    // MARK: - 4. affected_users aggregation

    @Test("Campaign aggregates affected_users from contributing alerts")
    func aggregateAffectedUsers() async throws {
        // Build a Campaign via the public initializer — same path the
        // CampaignDetector takes when emitting one. Three alerts, two
        // distinct user IDs (`501` twice, `502` once).
        let now = Date()
        let alerts: [CampaignDetector.AlertSummary] = [
            .init(ruleId: "r1", ruleTitle: "t1", severity: .high,
                  userId: "501", timestamp: now, tactics: ["execution"]),
            .init(ruleId: "r2", ruleTitle: "t2", severity: .high,
                  userId: "502", timestamp: now, tactics: ["persistence"]),
            .init(ruleId: "r3", ruleTitle: "t3", severity: .high,
                  userId: "501", timestamp: now, tactics: ["exfiltration"]),
        ]
        let campaign = CampaignDetector.Campaign(
            id: "c-users",
            type: .killChain,
            severity: .high,
            title: "T",
            description: "D",
            alerts: alerts,
            tactics: ["execution", "persistence", "exfiltration"],
            timeSpanSeconds: 1,
            detectedAt: now
        )
        #expect(campaign.affectedUsers == Set(["501", "502"]))
    }

    // MARK: - 5. affected_executables de-dup

    @Test("Campaign aggregates affected_executables (de-duplicated)")
    func aggregateAffectedExecutables() async throws {
        let now = Date()
        let alerts: [CampaignDetector.AlertSummary] = [
            .init(ruleId: "r1", ruleTitle: "t1", severity: .high,
                  processPath: "/usr/bin/curl", timestamp: now),
            .init(ruleId: "r2", ruleTitle: "t2", severity: .high,
                  processPath: "/bin/sh", timestamp: now),
            .init(ruleId: "r3", ruleTitle: "t3", severity: .high,
                  processPath: "/usr/bin/curl", timestamp: now),
            // nil path should be dropped, not collapse into ""
            .init(ruleId: "r4", ruleTitle: "t4", severity: .high,
                  processPath: nil, timestamp: now),
        ]
        let c = CampaignDetector.Campaign(
            id: "c-execs", type: .coordinatedAttack, severity: .high,
            title: "T", description: "D", alerts: alerts,
            tactics: [], timeSpanSeconds: 1, detectedAt: now
        )
        #expect(c.affectedExecutables == Set(["/usr/bin/curl", "/bin/sh"]))
    }

    // MARK: - 6. first_seen / last_seen bracket

    @Test("first_seen and last_seen bracket the campaign's alert timestamps")
    func firstLastSeenBracket() async throws {
        let base = Date(timeIntervalSince1970: 1_700_000_000)
        let early = base
        let mid   = base.addingTimeInterval(30)
        let late  = base.addingTimeInterval(90)
        let alerts: [CampaignDetector.AlertSummary] = [
            .init(ruleId: "a", ruleTitle: "a", severity: .high, timestamp: mid),
            .init(ruleId: "b", ruleTitle: "b", severity: .high, timestamp: late),
            .init(ruleId: "c", ruleTitle: "c", severity: .high, timestamp: early),
        ]
        let c = CampaignDetector.Campaign(
            id: "c-times", type: .killChain, severity: .high,
            title: "T", description: "D", alerts: alerts,
            tactics: [], timeSpanSeconds: 90, detectedAt: late
        )
        #expect(c.firstSeen == early)
        #expect(c.lastSeen == late)
    }

    // MARK: - 7. process_tree_depth max

    @Test("process_tree_depth picks the max across contributing alerts")
    func processTreeDepthMax() async throws {
        let now = Date()
        let alerts: [CampaignDetector.AlertSummary] = [
            .init(ruleId: "a", ruleTitle: "a", severity: .high,
                  timestamp: now, processTreeDepth: 2),
            .init(ruleId: "b", ruleTitle: "b", severity: .high,
                  timestamp: now, processTreeDepth: 7),
            .init(ruleId: "c", ruleTitle: "c", severity: .high,
                  timestamp: now, processTreeDepth: 5),
            // nil depth should not lower the max
            .init(ruleId: "d", ruleTitle: "d", severity: .high,
                  timestamp: now, processTreeDepth: nil),
        ]
        let c = CampaignDetector.Campaign(
            id: "c-depth", type: .killChain, severity: .high,
            title: "T", description: "D", alerts: alerts,
            tactics: [], timeSpanSeconds: 1, detectedAt: now
        )
        #expect(c.processTreeDepth == 7)
    }

    // MARK: - 8. techniques de-dup

    @Test("techniques aggregates MITRE techniques from contributing alerts (de-duplicated)")
    func aggregateTechniques() async throws {
        let now = Date()
        let alerts: [CampaignDetector.AlertSummary] = [
            .init(ruleId: "a", ruleTitle: "a", severity: .high,
                  timestamp: now, mitreTechniques: ["T1059.004", "T1547.001"]),
            .init(ruleId: "b", ruleTitle: "b", severity: .high,
                  timestamp: now, mitreTechniques: ["T1547.001"]),
            .init(ruleId: "c", ruleTitle: "c", severity: .high,
                  timestamp: now, mitreTechniques: ["T1003.001"]),
        ]
        let c = CampaignDetector.Campaign(
            id: "c-tech", type: .killChain, severity: .high,
            title: "T", description: "D", alerts: alerts,
            tactics: [], timeSpanSeconds: 1, detectedAt: now
        )
        #expect(c.techniques == Set(["T1059.004", "T1547.001", "T1003.001"]))
    }

    // MARK: - 9. ai_tools de-dup + nil for non-AI

    @Test("ai_tools aggregates values (de-duplicated, empty for non-AI campaigns)")
    func aggregateAITools() async throws {
        let now = Date()

        // 9a. AI-flavoured campaign: claude_code + cursor + claude_code → 2 distinct
        let aiAlerts: [CampaignDetector.AlertSummary] = [
            .init(ruleId: "a", ruleTitle: "a", severity: .high,
                  timestamp: now, aiTool: "claude_code"),
            .init(ruleId: "b", ruleTitle: "b", severity: .high,
                  timestamp: now, aiTool: "cursor"),
            .init(ruleId: "c", ruleTitle: "c", severity: .high,
                  timestamp: now, aiTool: "claude_code"),
        ]
        let aiCampaign = CampaignDetector.Campaign(
            id: "c-ai", type: .aiCompromise, severity: .critical,
            title: "T", description: "D", alerts: aiAlerts,
            tactics: [], timeSpanSeconds: 1, detectedAt: now
        )
        #expect(aiCampaign.aiTools == Set(["claude_code", "cursor"]))

        // 9b. Non-AI campaign — aiTool is nil on every alert. Aggregate
        // is empty, and the persistence layer translates that to NULL.
        let plainAlerts: [CampaignDetector.AlertSummary] = [
            .init(ruleId: "x", ruleTitle: "x", severity: .high,
                  timestamp: now),
            .init(ruleId: "y", ruleTitle: "y", severity: .high,
                  timestamp: now),
        ]
        let plainCampaign = CampaignDetector.Campaign(
            id: "c-plain", type: .killChain, severity: .high,
            title: "T", description: "D", alerts: plainAlerts,
            tactics: [], timeSpanSeconds: 1, detectedAt: now
        )
        #expect(plainCampaign.aiTools.isEmpty)

        // 9c. Round-trip the non-AI campaign through the store: ai_tools
        // column is bound NULL when the aggregate is empty.
        let path = makeTempPath()
        defer { cleanup(path) }
        let store = try CampaignStore(path: path)
        let record = CampaignStore.Record(
            id: "c-plain",
            type: "kill_chain",
            severity: .high,
            title: "T",
            description: "D",
            tactics: [],
            timeSpanSeconds: 1,
            detectedAt: now,
            aiTools: nil // empty set persisted as nil per EventLoop policy
        )
        try await store.insert(record)
        let fetched = try #require(try await store.get(id: "c-plain"))
        #expect(fetched.aiTools == nil)
    }

    // MARK: - 10. JSON round-trip

    @Test("Round-trip serialization preserves JSON arrays")
    func roundTripJSONArrays() async throws {
        let path = makeTempPath()
        defer { cleanup(path) }
        let store = try CampaignStore(path: path)

        let now = Date(timeIntervalSince1970: 1_700_000_500)
        let earlier = Date(timeIntervalSince1970: 1_700_000_400)
        let later = Date(timeIntervalSince1970: 1_700_000_600)

        let record = CampaignStore.Record(
            id: "roundtrip",
            type: "kill_chain",
            severity: .critical,
            title: "Round trip",
            description: "All v2 fields populated",
            tactics: ["execution", "persistence"],
            timeSpanSeconds: 200,
            detectedAt: now,
            alerts: [ref(processPath: "/bin/sh", userId: "501", tactics: ["execution"])],
            affectedUsers: ["501", "502"],
            affectedExecutables: ["/bin/sh", "/usr/bin/curl"],
            firstSeen: earlier,
            lastSeen: later,
            processTreeDepth: 5,
            techniques: ["T1059.004", "T1547.001"],
            aiTools: ["claude_code"]
        )
        try await store.insert(record)

        // Read back via the public API — exercises decoder + raw_json path.
        let fetched = try #require(try await store.get(id: "roundtrip"))
        #expect(fetched.affectedUsers == ["501", "502"])
        #expect(fetched.affectedExecutables == ["/bin/sh", "/usr/bin/curl"])
        #expect(fetched.firstSeen?.timeIntervalSince1970 == earlier.timeIntervalSince1970)
        #expect(fetched.lastSeen?.timeIntervalSince1970 == later.timeIntervalSince1970)
        #expect(fetched.processTreeDepth == 5)
        #expect(fetched.techniques == ["T1059.004", "T1547.001"])
        #expect(fetched.aiTools == ["claude_code"])

        // Sanity-check the indexed columns are populated too (not just raw_json).
        let raw = try #require(openRaw(at: path))
        defer { sqlite3_close(raw) }
        var stmt: OpaquePointer?
        #expect(sqlite3_prepare_v2(
            raw,
            "SELECT affected_users, affected_executables, first_seen, last_seen, process_tree_depth, techniques, ai_tools FROM campaigns WHERE id = ?1",
            -1, &stmt, nil
        ) == SQLITE_OK)
        let probe = try #require(stmt)
        let SQLITE_TRANSIENT = unsafeBitCast(-1, to: sqlite3_destructor_type.self)
        sqlite3_bind_text(probe, 1, "roundtrip", -1, SQLITE_TRANSIENT)
        #expect(sqlite3_step(probe) == SQLITE_ROW)
        // affected_users is a JSON string array
        let usersJSON = String(cString: sqlite3_column_text(probe, 0))
        #expect(usersJSON.contains("501") && usersJSON.contains("502"))
        // first_seen and last_seen are REAL
        #expect(sqlite3_column_double(probe, 2) == earlier.timeIntervalSince1970)
        #expect(sqlite3_column_double(probe, 3) == later.timeIntervalSince1970)
        // process_tree_depth is INTEGER
        #expect(sqlite3_column_int(probe, 4) == 5)
        // techniques + ai_tools are JSON arrays
        let techJSON = String(cString: sqlite3_column_text(probe, 5))
        #expect(techJSON.contains("T1059.004"))
        let aiJSON = String(cString: sqlite3_column_text(probe, 6))
        #expect(aiJSON.contains("claude_code"))
        sqlite3_finalize(probe)
    }
}
