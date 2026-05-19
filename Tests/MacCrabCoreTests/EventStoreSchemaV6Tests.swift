// EventStoreSchemaV6Tests.swift
// v1.12.6 Wave 2A regression pin — events.db schema v6 promotes 16
// high-value fields from raw_json into indexed columns and adds the
// matching Sigma resolver aliases. These tests pin:
//
//   - the v5 → v6 ALTER chain runs cleanly and leaves historical rows intact
//   - a fresh DB lands at user_version = 6 with the new columns + indexes
//   - insert() correctly projects ProcessInfo / TCCInfo / enrichments
//     into the new SQL columns (NULL convention preserved)
//   - RuleEngine resolves the new Sigma aliases (Architecture, IsNotarized,
//     NotarizationStatus, User, UserId, AiTool, ...) against the in-memory
//     Event struct so rules previously dead-lettered now fire
//   - historical raw_json round-trip still works (rules match against
//     deserialized Event regardless of whether the v6 columns are NULL)

import Testing
import Foundation
import CSQLCipher
@testable import MacCrabCore

@Suite("EventStore: schema v6 column projection + Sigma aliases (v1.12.6 Wave 2A)")
struct EventStoreSchemaV6Tests {

    // MARK: - Helpers

    private static func tempPath() -> String {
        FileManager.default.temporaryDirectory
            .appendingPathComponent("schema-v6-\(UUID().uuidString).db").path
    }

    /// Read the user_version pragma off a raw handle.
    private static func userVersion(of db: OpaquePointer) -> Int {
        var stmt: OpaquePointer?
        defer { sqlite3_finalize(stmt) }
        guard sqlite3_prepare_v2(db, "PRAGMA user_version", -1, &stmt, nil) == SQLITE_OK,
              sqlite3_step(stmt) == SQLITE_ROW else {
            return -1
        }
        return Int(sqlite3_column_int(stmt, 0))
    }

    /// True iff the `events` table has `column`.
    private static func eventsHasColumn(_ db: OpaquePointer, _ column: String) -> Bool {
        var stmt: OpaquePointer?
        defer { sqlite3_finalize(stmt) }
        guard sqlite3_prepare_v2(db, "PRAGMA table_info(events)", -1, &stmt, nil) == SQLITE_OK else { return false }
        while sqlite3_step(stmt) == SQLITE_ROW {
            if let cstr = sqlite3_column_text(stmt, 1), String(cString: cstr) == column {
                return true
            }
        }
        return false
    }

    /// True iff the named index exists in sqlite_master.
    private static func indexExists(_ db: OpaquePointer, _ name: String) -> Bool {
        var stmt: OpaquePointer?
        defer { sqlite3_finalize(stmt) }
        let sql = "SELECT 1 FROM sqlite_master WHERE type='index' AND name=?1"
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else { return false }
        let TRANSIENT = unsafeBitCast(OpaquePointer(bitPattern: -1)!, to: sqlite3_destructor_type.self)
        sqlite3_bind_text(stmt, 1, name, -1, TRANSIENT)
        return sqlite3_step(stmt) == SQLITE_ROW
    }

    /// A canonical fixture process — populated enough to exercise every
    /// new column we project. Caller can override individual fields.
    private static func makeProcess(
        userId: UInt32 = 501,
        userName: String = "alice",
        groupId: UInt32 = 20,
        workingDirectory: String = "/Users/alice",
        rpid: Int32 = 99,
        architecture: String? = "arm64",
        isPlatformBinary: Bool = false,
        isNotarized: Bool = true,
        sha256: String? = "deadbeef00000000000000000000000000000000000000000000000000000000",
        ancestors: [ProcessAncestor] = [
            ProcessAncestor(pid: 100, executable: "/usr/bin/zsh", name: "zsh"),
        ],
        launchSource: LaunchSource? = .terminal
    ) -> MacCrabCore.ProcessInfo {
        let sig = CodeSignatureInfo(
            signerType: .devId,
            teamId: "TEAM123",
            signingId: "com.acme.tool",
            authorities: [],
            flags: 0,
            isNotarized: isNotarized
        )
        return MacCrabCore.ProcessInfo(
            pid: 1234,
            ppid: 100,
            rpid: rpid,
            name: "acme",
            executable: "/Applications/Acme.app/Contents/MacOS/acme",
            commandLine: "/Applications/Acme.app/Contents/MacOS/acme --run",
            args: ["acme", "--run"],
            workingDirectory: workingDirectory,
            userId: userId,
            userName: userName,
            groupId: groupId,
            startTime: Date(),
            codeSignature: sig,
            ancestors: ancestors,
            architecture: architecture,
            isPlatformBinary: isPlatformBinary,
            hashes: sha256.map { ProcessHashes(sha256: $0, cdhash: nil, md5: nil) },
            session: launchSource.map { SessionInfo(launchSource: $0) }
        )
    }

    /// Build a process_creation Event with the given process.
    private static func makeEvent(
        process: MacCrabCore.ProcessInfo,
        tcc: TCCInfo? = nil,
        enrichments: [String: String] = [:]
    ) -> Event {
        Event(
            eventCategory: tcc == nil ? .process : .tcc,
            eventType: tcc == nil ? .start : .info,
            eventAction: tcc == nil ? "exec" : "tcc_grant",
            process: process,
            tcc: tcc,
            enrichments: enrichments
        )
    }

    // MARK: - Migration shape

    @Test("Fresh install lands at user_version = 6 with all new columns")
    func freshInstallV6() async throws {
        let path = Self.tempPath()
        defer { try? FileManager.default.removeItem(atPath: path) }
        _ = try EventStore(path: path)

        var db: OpaquePointer?
        defer { if let d = db { sqlite3_close(d) } }
        #expect(sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY, nil) == SQLITE_OK)
        guard let db else { return }

        #expect(Self.userVersion(of: db) == 6)
        for col in [
            "user_id", "user_name", "group_id", "working_directory",
            "responsible_pid", "architecture", "is_platform_binary",
            "is_notarized", "process_sha256", "parent_name",
            "parent_executable", "parent_signer_type", "ai_tool",
            "ai_tool_child", "session_launch_source", "tcc_decision",
        ] {
            #expect(Self.eventsHasColumn(db, col), "missing column: \(col)")
        }
        for idx in [
            "idx_events_user_id",
            "idx_events_ai_tool_ts",
            "idx_events_parent_exe_ts",
        ] {
            #expect(Self.indexExists(db, idx), "missing index: \(idx)")
        }
    }

    @Test("v5 → v6 migration preserves rows but writes NULL into new columns")
    func upgradeFromV5PreservesRowsWithNullCols() async throws {
        let path = Self.tempPath()
        defer { try? FileManager.default.removeItem(atPath: path) }

        // Build a v5 events.db by hand: same baseline CREATE TABLE
        // EventStore writes, plus the v2/v3/v4/v5 ALTERs, plus
        // PRAGMA user_version = 5. Then insert one row using only
        // the v5-known columns. Re-opening through EventStore must
        // upgrade to v6 cleanly + leave the row readable.
        var rawDB: OpaquePointer?
        guard sqlite3_open_v2(path, &rawDB,
                              SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
                              nil) == SQLITE_OK,
              let raw = rawDB else {
            Issue.record("could not open raw db at \(path)")
            return
        }

        let v5Schema = [
            """
            CREATE TABLE events (
                id TEXT PRIMARY KEY, timestamp REAL NOT NULL,
                event_category TEXT NOT NULL, event_type TEXT NOT NULL,
                event_action TEXT NOT NULL, severity TEXT NOT NULL,
                process_pid INTEGER, process_name TEXT, process_path TEXT,
                process_commandline TEXT, process_ppid INTEGER,
                process_signer TEXT, process_team_id TEXT, process_signing_id TEXT,
                file_path TEXT, file_action TEXT,
                network_dest_ip TEXT, network_dest_port INTEGER,
                tcc_service TEXT, tcc_client TEXT, raw_json TEXT NOT NULL
            )
            """,
            "ALTER TABLE events ADD COLUMN mcp_server_name TEXT",
            "ALTER TABLE events ADD COLUMN mcp_server_category TEXT",
            "ALTER TABLE events ADD COLUMN ai_tool_session_id TEXT",
            "ALTER TABLE events ADD COLUMN agent_trace_id TEXT",
            "ALTER TABLE events ADD COLUMN agent_span_id TEXT",
            "ALTER TABLE events ADD COLUMN agent_tool TEXT",
            "ALTER TABLE events ADD COLUMN machine_agent_confidence TEXT",
            "ALTER TABLE events ADD COLUMN agent_evidence_json TEXT",
            // Minimal row to confirm the migration is non-destructive.
            // raw_json carries a fake but parseable Event-like blob so
            // queryEvents() can still pretend to decode it (the test
            // here uses the raw SQLite handle, so JSON shape doesn't
            // matter to the migration itself).
            "INSERT INTO events (id, timestamp, event_category, event_type, event_action, severity, raw_json) VALUES ('legacy-row-1', 1700000000.0, 'process', 'start', 'exec', 'informational', '{}')",
            "PRAGMA user_version = 5",
        ]
        for sql in v5Schema {
            let rc = sqlite3_exec(raw, sql, nil, nil, nil)
            #expect(rc == SQLITE_OK, "v5 setup failed at: \(sql)")
        }
        sqlite3_close(raw)

        // Reopen via EventStore — migration should kick in.
        let store = try EventStore(path: path)
        // Use the actor's count() to confirm the legacy row survived.
        let count = try await store.count()
        #expect(count == 1, "legacy row vanished during v5 → v6 migration")

        // Verify user_version bumped to 6 and the new columns are NULL
        // for the legacy row.
        var verifyDB: OpaquePointer?
        defer { if let d = verifyDB { sqlite3_close(d) } }
        sqlite3_open_v2(path, &verifyDB, SQLITE_OPEN_READONLY, nil)
        guard let v = verifyDB else { return }
        #expect(Self.userVersion(of: v) == 6)

        var stmt: OpaquePointer?
        defer { sqlite3_finalize(stmt) }
        let sql = """
            SELECT user_id, user_name, architecture, is_notarized,
                   parent_executable, ai_tool, tcc_decision
            FROM events WHERE id = 'legacy-row-1'
            """
        guard sqlite3_prepare_v2(v, sql, -1, &stmt, nil) == SQLITE_OK,
              sqlite3_step(stmt) == SQLITE_ROW else {
            Issue.record("could not read legacy row back")
            return
        }
        // All seven new columns must be NULL for pre-v6 rows.
        for i: Int32 in 0..<7 {
            #expect(sqlite3_column_type(stmt, i) == SQLITE_NULL,
                    "pre-v6 column \(i) was not NULL")
        }
    }

    @Test("Migration v6 is idempotent — re-opening preserves user_version=6")
    func migrationIsIdempotent() async throws {
        let path = Self.tempPath()
        defer { try? FileManager.default.removeItem(atPath: path) }
        _ = try EventStore(path: path)
        _ = try EventStore(path: path)
        _ = try EventStore(path: path)

        var db: OpaquePointer?
        defer { if let d = db { sqlite3_close(d) } }
        sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY, nil)
        guard let db else { return }
        #expect(Self.userVersion(of: db) == 6)
    }

    // MARK: - Insert column projection

    @Test("insert(event:) populates all v6 columns from a fully-fleshed Event")
    func insertPopulatesColumns() async throws {
        let path = Self.tempPath()
        defer { try? FileManager.default.removeItem(atPath: path) }
        let store = try EventStore(path: path)

        let proc = Self.makeProcess(
            userId: 501, userName: "alice",
            groupId: 20, workingDirectory: "/Users/alice/work",
            rpid: 99, architecture: "arm64",
            isPlatformBinary: false, isNotarized: true,
            sha256: "deadbeef00000000000000000000000000000000000000000000000000000000",
            ancestors: [
                ProcessAncestor(pid: 100, executable: "/Applications/Claude.app/Contents/MacOS/Claude", name: "Claude"),
            ],
            launchSource: .terminal
        )
        var ev = Self.makeEvent(process: proc)
        ev.enrichments[TraceCorrelator.EnrichmentKey.agentTool] = "claude_code"
        ev.enrichments["ai_tool_child"] = "true"
        ev.enrichments["ParentSignerType"] = "devId"
        try await store.insert(event: ev)

        var db: OpaquePointer?
        defer { if let d = db { sqlite3_close(d) } }
        sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY, nil)
        guard let db else { return }

        let sql = """
            SELECT user_id, user_name, group_id, working_directory,
                   responsible_pid, architecture, is_platform_binary,
                   is_notarized, process_sha256, parent_name,
                   parent_executable, parent_signer_type, ai_tool,
                   ai_tool_child, session_launch_source, tcc_decision
            FROM events
            """
        var stmt: OpaquePointer?
        defer { sqlite3_finalize(stmt) }
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK,
              sqlite3_step(stmt) == SQLITE_ROW else {
            Issue.record("could not read row back")
            return
        }
        #expect(sqlite3_column_int64(stmt, 0) == 501)               // user_id
        #expect(String(cString: sqlite3_column_text(stmt, 1)) == "alice")
        #expect(sqlite3_column_int64(stmt, 2) == 20)                // group_id
        #expect(String(cString: sqlite3_column_text(stmt, 3)) == "/Users/alice/work")
        #expect(sqlite3_column_int(stmt, 4) == 99)                  // responsible_pid
        #expect(String(cString: sqlite3_column_text(stmt, 5)) == "arm64")
        #expect(sqlite3_column_int(stmt, 6) == 0)                   // is_platform_binary (false)
        #expect(sqlite3_column_int(stmt, 7) == 1)                   // is_notarized (true)
        #expect(String(cString: sqlite3_column_text(stmt, 8)).hasPrefix("deadbeef"))
        #expect(String(cString: sqlite3_column_text(stmt, 9)) == "Claude")
        #expect(String(cString: sqlite3_column_text(stmt, 10)).contains("Claude.app"))
        #expect(String(cString: sqlite3_column_text(stmt, 11)) == "devId")
        #expect(String(cString: sqlite3_column_text(stmt, 12)) == "claude_code")
        #expect(sqlite3_column_int(stmt, 13) == 1)                  // ai_tool_child
        #expect(String(cString: sqlite3_column_text(stmt, 14)) == "terminal")
        // tcc_decision is NULL for process events.
        #expect(sqlite3_column_type(stmt, 15) == SQLITE_NULL)
    }

    @Test("Empty userName / workingDirectory bind as NULL, not empty string")
    func emptyStringsBindAsNull() async throws {
        let path = Self.tempPath()
        defer { try? FileManager.default.removeItem(atPath: path) }
        let store = try EventStore(path: path)

        let proc = Self.makeProcess(
            userName: "",                  // empty -> NULL
            workingDirectory: "",          // empty -> NULL
            ancestors: [],                 // no ancestors -> parent_* NULL
            launchSource: nil              // session_launch_source NULL
        )
        let ev = Self.makeEvent(process: proc)
        try await store.insert(event: ev)

        var db: OpaquePointer?
        defer { if let d = db { sqlite3_close(d) } }
        sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY, nil)
        guard let db else { return }

        var stmt: OpaquePointer?
        defer { sqlite3_finalize(stmt) }
        let sql = """
            SELECT user_name, working_directory, parent_name,
                   parent_executable, session_launch_source
            FROM events
            """
        sqlite3_prepare_v2(db, sql, -1, &stmt, nil)
        #expect(sqlite3_step(stmt) == SQLITE_ROW)
        for i: Int32 in 0..<5 {
            #expect(sqlite3_column_type(stmt, i) == SQLITE_NULL,
                    "column \(i) should be NULL for empty/missing source")
        }
    }

    @Test("isPlatformBinary stores as 0/1 INTEGER (not 'true'/'false')")
    func boolsStoreAsInteger() async throws {
        let path = Self.tempPath()
        defer { try? FileManager.default.removeItem(atPath: path) }
        let store = try EventStore(path: path)

        let procTrue = Self.makeProcess(isPlatformBinary: true)
        let procFalse = Self.makeProcess(userName: "bob", isPlatformBinary: false)
        try await store.insert(event: Self.makeEvent(process: procTrue))
        try await store.insert(event: Self.makeEvent(process: procFalse))

        var db: OpaquePointer?
        defer { if let d = db { sqlite3_close(d) } }
        sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY, nil)
        guard let db else { return }
        var stmt: OpaquePointer?
        defer { sqlite3_finalize(stmt) }
        let sql = "SELECT is_platform_binary FROM events ORDER BY rowid"
        sqlite3_prepare_v2(db, sql, -1, &stmt, nil)
        #expect(sqlite3_step(stmt) == SQLITE_ROW)
        #expect(sqlite3_column_type(stmt, 0) == SQLITE_INTEGER)
        #expect(sqlite3_column_int(stmt, 0) == 1)
        #expect(sqlite3_step(stmt) == SQLITE_ROW)
        #expect(sqlite3_column_int(stmt, 0) == 0)
    }

    @Test("isNotarized is NULL when codeSignature is missing")
    func nullNotarizedWhenNoSignature() async throws {
        let path = Self.tempPath()
        defer { try? FileManager.default.removeItem(atPath: path) }
        let store = try EventStore(path: path)

        let proc = MacCrabCore.ProcessInfo(
            pid: 1, ppid: 0, rpid: 0,
            name: "x", executable: "/tmp/x", commandLine: "/tmp/x",
            args: [], workingDirectory: "/tmp",
            userId: 0, userName: "root", groupId: 0,
            startTime: Date(),
            codeSignature: nil,             // <-- the crux
            ancestors: [],
            architecture: nil, isPlatformBinary: false
        )
        try await store.insert(event: Self.makeEvent(process: proc))

        var db: OpaquePointer?
        defer { if let d = db { sqlite3_close(d) } }
        sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY, nil)
        guard let db else { return }
        var stmt: OpaquePointer?
        defer { sqlite3_finalize(stmt) }
        sqlite3_prepare_v2(db, "SELECT is_notarized, architecture FROM events", -1, &stmt, nil)
        #expect(sqlite3_step(stmt) == SQLITE_ROW)
        #expect(sqlite3_column_type(stmt, 0) == SQLITE_NULL,
                "is_notarized should be NULL when no codeSignature")
        #expect(sqlite3_column_type(stmt, 1) == SQLITE_NULL,
                "architecture should be NULL when unset")
    }

    @Test("TCC events project tcc_decision as 'granted' / 'denied'")
    func tccDecisionProjection() async throws {
        let path = Self.tempPath()
        defer { try? FileManager.default.removeItem(atPath: path) }
        let store = try EventStore(path: path)

        let proc = Self.makeProcess()
        let grant = TCCInfo(
            service: "kTCCServiceCamera",
            client: "com.evil.app",
            clientPath: "/Applications/Evil.app",
            allowed: true,
            authReason: "user_consent"
        )
        let deny = TCCInfo(
            service: "kTCCServiceMicrophone",
            client: "com.evil.app",
            clientPath: "/Applications/Evil.app",
            allowed: false,
            authReason: "system_policy"
        )
        try await store.insert(event: Self.makeEvent(process: proc, tcc: grant))
        try await store.insert(event: Self.makeEvent(process: proc, tcc: deny))

        var db: OpaquePointer?
        defer { if let d = db { sqlite3_close(d) } }
        sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY, nil)
        guard let db else { return }
        var stmt: OpaquePointer?
        defer { sqlite3_finalize(stmt) }
        sqlite3_prepare_v2(db, "SELECT tcc_decision FROM events ORDER BY rowid", -1, &stmt, nil)
        #expect(sqlite3_step(stmt) == SQLITE_ROW)
        #expect(String(cString: sqlite3_column_text(stmt, 0)) == "granted")
        #expect(sqlite3_step(stmt) == SQLITE_ROW)
        #expect(String(cString: sqlite3_column_text(stmt, 0)) == "denied")
    }

    // MARK: - RuleEngine resolver coverage (regression for Findings 1 + 2)

    /// Build a single-predicate CompiledRule that fires when the
    /// resolver returns a value equal to `expected` for `field`.
    private static func equalsRule(
        ruleId: String,
        field: String,
        equals expected: String,
        category: String = "process_creation"
    ) -> CompiledRule {
        let predicate = Predicate(
            field: field, modifier: .equals,
            values: [expected], negate: false
        )
        return CompiledRule(
            id: ruleId,
            title: "Test \(field)",
            description: "regression for v1.12.6 Wave 2A",
            level: .high,
            tags: [],
            logsource: LogSource(category: category, product: "macos"),
            predicates: [predicate],
            condition: .allOf,
            falsepositives: []
        )
    }

    /// Inject one CompiledRule into the engine via the public load-from-
    /// directory API. Writes a synthetic JSON file into a temp dir and
    /// asks the engine to load it.
    private static func loadSingleRule(_ rule: CompiledRule) async throws -> RuleEngine {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("v6-rule-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let url = dir.appendingPathComponent("\(rule.id).json")
        try JSONEncoder().encode(rule).write(to: url)
        let engine = RuleEngine()
        _ = try await engine.loadRules(from: dir)
        return engine
    }

    @Test("RuleEngine resolves Architecture: 'x86_64' (closes Finding 2)")
    func resolverArchitecture() async throws {
        let engine = try await Self.loadSingleRule(
            Self.equalsRule(ruleId: "test_arch", field: "Architecture", equals: "x86_64")
        )
        let proc = Self.makeProcess(architecture: "x86_64")
        let matches = await engine.evaluate(Self.makeEvent(process: proc))
        #expect(matches.contains { $0.ruleId == "test_arch" },
                "Architecture: 'x86_64' must fire (rosetta rules were dead)")
    }

    @Test("RuleEngine resolves NotarizationStatus: 'not_notarized' (closes Finding 1)")
    func resolverNotarizationStatus() async throws {
        let engine = try await Self.loadSingleRule(
            Self.equalsRule(ruleId: "test_notar", field: "NotarizationStatus", equals: "not_notarized")
        )
        let proc = Self.makeProcess(isNotarized: false)
        let matches = await engine.evaluate(Self.makeEvent(process: proc))
        #expect(matches.contains { $0.ruleId == "test_notar" },
                "NotarizationStatus: 'not_notarized' must fire (notarization rules were dead)")
    }

    @Test("NotarizationStatus = 'notarized' fires for a notarized signature")
    func resolverNotarizationStatusPositive() async throws {
        let engine = try await Self.loadSingleRule(
            Self.equalsRule(ruleId: "test_notar2", field: "NotarizationStatus", equals: "notarized")
        )
        let proc = Self.makeProcess(isNotarized: true)
        let matches = await engine.evaluate(Self.makeEvent(process: proc))
        #expect(matches.contains { $0.ruleId == "test_notar2" })
    }

    @Test("NotarizationStatus is nil for a process with no codeSignature (no false match)")
    func resolverNotarizationStatusNilWithoutSignature() async throws {
        // Rule expects "not_notarized" — but the process has NO
        // codeSignature, so the resolver returns nil and the rule
        // must NOT fire (no spurious matches on early-life processes
        // where the enricher hasn't attached signature info yet).
        let engine = try await Self.loadSingleRule(
            Self.equalsRule(ruleId: "test_notar3", field: "NotarizationStatus", equals: "not_notarized")
        )
        let proc = MacCrabCore.ProcessInfo(
            pid: 1, ppid: 0, rpid: 0,
            name: "x", executable: "/tmp/x", commandLine: "/tmp/x",
            args: [], workingDirectory: "/tmp",
            userId: 0, userName: "root", groupId: 0,
            startTime: Date(),
            codeSignature: nil,
            ancestors: [],
            architecture: nil, isPlatformBinary: false
        )
        let matches = await engine.evaluate(Self.makeEvent(process: proc))
        #expect(!matches.contains { $0.ruleId == "test_notar3" },
                "Rule must NOT fire when codeSignature is nil")
    }

    @Test("RuleEngine resolves User and UserId aliases")
    func resolverUserAndUserId() async throws {
        let engineUser = try await Self.loadSingleRule(
            Self.equalsRule(ruleId: "test_user", field: "User", equals: "alice")
        )
        let proc = Self.makeProcess(userId: 501, userName: "alice")
        let userMatches = await engineUser.evaluate(Self.makeEvent(process: proc))
        #expect(userMatches.contains { $0.ruleId == "test_user" })

        let engineId = try await Self.loadSingleRule(
            Self.equalsRule(ruleId: "test_uid", field: "UserId", equals: "501")
        )
        let idMatches = await engineId.evaluate(Self.makeEvent(process: proc))
        #expect(idMatches.contains { $0.ruleId == "test_uid" })
    }

    @Test("RuleEngine resolves AiTool / AITool aliases against agent_tool enrichment")
    func resolverAiTool() async throws {
        let engine1 = try await Self.loadSingleRule(
            Self.equalsRule(ruleId: "test_aitool", field: "AiTool", equals: "claude_code")
        )
        let engine2 = try await Self.loadSingleRule(
            Self.equalsRule(ruleId: "test_aitool2", field: "AITool", equals: "claude_code")
        )
        let proc = Self.makeProcess()
        var ev = Self.makeEvent(process: proc)
        ev.enrichments[TraceCorrelator.EnrichmentKey.agentTool] = "claude_code"
        #expect(await engine1.evaluate(ev).contains { $0.ruleId == "test_aitool" })
        #expect(await engine2.evaluate(ev).contains { $0.ruleId == "test_aitool2" })
    }

    @Test("RuleEngine resolves IsNotarized as a string Bool")
    func resolverIsNotarized() async throws {
        let engine = try await Self.loadSingleRule(
            Self.equalsRule(ruleId: "test_isnot", field: "IsNotarized", equals: "false")
        )
        let proc = Self.makeProcess(isNotarized: false)
        let matches = await engine.evaluate(Self.makeEvent(process: proc))
        #expect(matches.contains { $0.ruleId == "test_isnot" })
    }

    @Test("RuleEngine resolves ParentName and WorkingDirectory")
    func resolverParentNameAndWorkingDirectory() async throws {
        let engine1 = try await Self.loadSingleRule(
            Self.equalsRule(ruleId: "test_parent_name", field: "ParentName", equals: "zsh")
        )
        let engine2 = try await Self.loadSingleRule(
            Self.equalsRule(ruleId: "test_wd", field: "WorkingDirectory", equals: "/Users/alice")
        )
        let proc = Self.makeProcess(
            workingDirectory: "/Users/alice",
            ancestors: [ProcessAncestor(pid: 100, executable: "/bin/zsh", name: "zsh")]
        )
        let ev = Self.makeEvent(process: proc)
        #expect(await engine1.evaluate(ev).contains { $0.ruleId == "test_parent_name" })
        #expect(await engine2.evaluate(ev).contains { $0.ruleId == "test_wd" })
    }

    @Test("RuleEngine resolves FileAction Sigma alias (Wave 7A.1 regression)")
    func resolverFileActionAlias() async throws {
        // FileAction was listed in `_KNOWN_PASSTHROUGH_FIELDS` in the
        // compile_rules.py compiler but had no case in
        // RuleEngine.resolveField — so 15+ ai_safety / supply_chain
        // rules that predicate on `FileAction: 'create'` etc. silently
        // never fired. Pin both the dot-form ("file.action") and the
        // Sigma-form ("FileAction") here.
        let engineDotForm = try await Self.loadSingleRule(
            Self.equalsRule(
                ruleId: "test_file_action_dot",
                field: "file.action",
                equals: "create",
                category: "file_event"
            )
        )
        let engineSigmaAlias = try await Self.loadSingleRule(
            Self.equalsRule(
                ruleId: "test_file_action_sigma",
                field: "FileAction",
                equals: "create",
                category: "file_event"
            )
        )
        let proc = Self.makeProcess()
        let file = FileInfo(
            path: "/tmp/x", size: 0,
            action: .create
        )
        let ev = Event(
            eventCategory: .file,
            eventType: .creation,
            eventAction: "file_create",
            process: proc,
            file: file
        )
        #expect(await engineDotForm.evaluate(ev).contains { $0.ruleId == "test_file_action_dot" },
                "file.action: 'create' must fire")
        #expect(await engineSigmaAlias.evaluate(ev).contains { $0.ruleId == "test_file_action_sigma" },
                "FileAction: 'create' must fire (Sigma-style alias was dead pre-Wave 7A)")
    }

    // MARK: - Historical row backward-compat

    @Test("Round-trip from raw_json reconstructs the resolver-relevant fields")
    func roundTripFromRawJson() async throws {
        // Direct regression for the "historical NULL columns" worry:
        // events.db queryEvents reads ONLY raw_json, then decodes
        // Event. So even if v6 columns are NULL on a pre-v6 row, the
        // resolver still sees full ProcessInfo (because raw_json
        // contains it). This pins that contract.
        let path = Self.tempPath()
        defer { try? FileManager.default.removeItem(atPath: path) }
        let store = try EventStore(path: path)

        let proc = Self.makeProcess(
            userName: "carol",
            architecture: "x86_64",
            isNotarized: false
        )
        let originalEvent = Self.makeEvent(process: proc)
        try await store.insert(event: originalEvent)

        let read = try await store.events(since: .distantPast)
        #expect(read.count == 1)
        guard let ev = read.first else { return }
        #expect(ev.process.userName == "carol")
        #expect(ev.process.architecture == "x86_64")
        #expect(ev.process.codeSignature?.isNotarized == false)

        // And the resolver still fires on the read-back event — proves
        // the rules don't need the v6 SQL columns to work; the Event
        // struct rebuilt from raw_json is the source of truth.
        let engine = try await Self.loadSingleRule(
            Self.equalsRule(ruleId: "rb_notar", field: "NotarizationStatus", equals: "not_notarized")
        )
        let matches = await engine.evaluate(ev)
        #expect(matches.contains { $0.ruleId == "rb_notar" },
                "Resolver must fire on event reconstructed from raw_json")
    }

    // MARK: - SQLite row-size budget guard

    @Test("Row with all v6 columns + 32 KB raw_json inserts without truncation (under Wave 1C cap)")
    func largeRowBudgetGuard() async throws {
        // SQLite has no per-row size limit in practice (default
        // SQLITE_MAX_LENGTH is 1 GB), but we want a guard that the
        // ~200-byte v6 column overhead never approaches a default
        // statement-builder limit. Insert one row well below the
        // Wave 1C payload cap (EventStore.maxRawJsonBytes = 65_536)
        // and confirm it round-trips intact — pushing past the cap
        // triggers Wave 1C's truncation pipeline, which is covered
        // separately by EventStorePayloadCapTests.
        let path = Self.tempPath()
        defer { try? FileManager.default.removeItem(atPath: path) }
        let store = try EventStore(path: path)

        let bigCmd = String(repeating: "X", count: 32_000)
        let proc = MacCrabCore.ProcessInfo(
            pid: 9, ppid: 1, rpid: 1,
            name: "huge", executable: "/usr/local/bin/huge",
            commandLine: bigCmd,
            args: ["huge"], workingDirectory: "/Users/alice",
            userId: 501, userName: "alice", groupId: 20,
            startTime: Date(),
            codeSignature: CodeSignatureInfo(
                signerType: .devId, teamId: "T", signingId: "x",
                authorities: [], flags: 0, isNotarized: true
            ),
            ancestors: [ProcessAncestor(pid: 100, executable: "/bin/zsh", name: "zsh")],
            architecture: "arm64", isPlatformBinary: false,
            hashes: ProcessHashes(sha256: String(repeating: "a", count: 64)),
            session: SessionInfo(launchSource: .terminal)
        )
        try await store.insert(event: Self.makeEvent(process: proc))

        let read = try await store.events(since: .distantPast)
        #expect(read.count == 1)
        // CommandSanitizer runs on insert; for a string of plain X's it
        // returns the input unchanged, so length must survive intact.
        #expect(read.first?.process.commandLine.count == 32_000)
    }
}
