// EventStoreSchemaV6Tests.swift
// v1.12.6 Wave 2A regression pin — events.db schema v6 promotes 16
// high-value fields from raw_json into indexed columns and adds the
// matching Sigma resolver aliases. These tests pin:
//
//   - the v5 → v8 chain preserves valid historical rows in the exact journal
//   - a fresh DB lands at user_version = 8 with the v6 columns while v7's
//     superseded indexes remain absent
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

    private static func tableExists(_ db: OpaquePointer, _ name: String) -> Bool {
        var stmt: OpaquePointer?
        defer { sqlite3_finalize(stmt) }
        let sql = "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1"
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else { return false }
        let transient = unsafeBitCast(OpaquePointer(bitPattern: -1)!, to: sqlite3_destructor_type.self)
        sqlite3_bind_text(stmt, 1, name, -1, transient)
        return sqlite3_step(stmt) == SQLITE_ROW
    }

    private static func scalarInt(_ db: OpaquePointer, _ sql: String) -> Int {
        var stmt: OpaquePointer?
        defer { sqlite3_finalize(stmt) }
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK,
              sqlite3_step(stmt) == SQLITE_ROW else {
            return -1
        }
        return Int(sqlite3_column_int64(stmt, 0))
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

    @Test("Fresh install lands at v8 with v6 columns and no superseded indexes")
    func freshInstallV6() async throws {
        let path = Self.tempPath()
        defer { try? FileManager.default.removeItem(atPath: path) }
        _ = try EventStore(path: path)

        var db: OpaquePointer?
        defer { if let d = db { sqlite3_close(d) } }
        #expect(sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY, nil) == SQLITE_OK)
        guard let db else { return }

        #expect(Self.userVersion(of: db) == 8)
        for col in [
            "user_id", "user_name", "group_id", "working_directory",
            "responsible_pid", "architecture", "is_platform_binary",
            "is_notarized", "process_sha256", "parent_name",
            "parent_executable", "parent_signer_type", "ai_tool",
            "ai_tool_child", "session_launch_source", "tcc_decision",
        ] {
            #expect(Self.eventsHasColumn(db, col), "missing column: \(col)")
        }
        // v7 deliberately removes these wide-table indexes; v8's authenticated
        // journal is exact truth and `events` is only a bounded projection.
        for idx in [
            "idx_events_user_id",
            "idx_events_ai_tool_ts",
            "idx_events_parent_exe_ts",
        ] {
            #expect(!Self.indexExists(db, idx), "superseded index survived: \(idx)")
        }
        for table in [
            "event_journal_blocks",
            "event_journal_migration",
            "event_projection_coverage",
        ] {
            #expect(Self.tableExists(db, table), "missing v8 table: \(table)")
        }
    }

    @Test("v5 → v8 migration journals a valid legacy row exactly and conserves recovery state")
    func upgradeFromV5PreservesRowsWithNullCols() async throws {
        let path = Self.tempPath()
        defer { try? FileManager.default.removeItem(atPath: path) }

        // Build a v5 events.db by hand. The source row must be a valid Event
        // whose v5 typed columns agree with raw_json: v8 intentionally
        // quarantines malformed or contradictory legacy evidence rather than
        // treating it as a countable row.
        let legacyID = UUID()
        let legacyTimestamp = Date()
        let legacyProcess = MacCrabCore.ProcessInfo(
            pid: 4242,
            ppid: 1,
            rpid: 1,
            name: "legacy-tool",
            executable: "/usr/bin/legacy-tool",
            commandLine: "/usr/bin/legacy-tool --safe",
            args: ["legacy-tool", "--safe"],
            workingDirectory: "/",
            userId: 501,
            userName: "legacy-user",
            groupId: 20,
            startTime: legacyTimestamp,
            ancestors: [],
            isPlatformBinary: false
        )
        let legacyEvent = Event(
            id: legacyID,
            timestamp: legacyTimestamp,
            eventCategory: .process,
            eventType: .start,
            eventAction: "exec",
            process: legacyProcess
        )
        let legacyJSONData = try JSONEncoder().encode(legacyEvent)
        let legacyJSON = try #require(String(data: legacyJSONData, encoding: .utf8))

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
            """
            CREATE VIRTUAL TABLE events_fts USING fts5(
                process_name, process_path, process_commandline,
                file_path, network_dest_ip, tcc_service, tcc_client,
                content=events, content_rowid=rowid
            )
            """,
            """
            CREATE TRIGGER events_ai AFTER INSERT ON events BEGIN
                INSERT INTO events_fts(
                    rowid, process_name, process_path, process_commandline,
                    file_path, network_dest_ip, tcc_service, tcc_client
                ) VALUES (
                    new.rowid, new.process_name, new.process_path,
                    new.process_commandline, new.file_path,
                    new.network_dest_ip, new.tcc_service, new.tcc_client
                );
            END
            """,
            "ALTER TABLE events ADD COLUMN mcp_server_name TEXT",
            "ALTER TABLE events ADD COLUMN mcp_server_category TEXT",
            "ALTER TABLE events ADD COLUMN ai_tool_session_id TEXT",
            "ALTER TABLE events ADD COLUMN agent_trace_id TEXT",
            "ALTER TABLE events ADD COLUMN agent_span_id TEXT",
            "ALTER TABLE events ADD COLUMN agent_tool TEXT",
            "ALTER TABLE events ADD COLUMN machine_agent_confidence TEXT",
            "ALTER TABLE events ADD COLUMN agent_evidence_json TEXT",
        ]
        for sql in v5Schema {
            let rc = sqlite3_exec(raw, sql, nil, nil, nil)
            #expect(rc == SQLITE_OK, "v5 setup failed at: \(sql)")
        }

        let insertSQL = """
            INSERT INTO events (
                id, timestamp, event_category, event_type, event_action,
                severity, process_pid, process_name, process_path,
                process_commandline, process_ppid, raw_json
            ) VALUES (?1, ?2, 'process', 'start', 'exec', 'informational',
                      ?3, ?4, ?5, ?6, ?7, ?8)
            """
        var insertStmt: OpaquePointer?
        #expect(sqlite3_prepare_v2(raw, insertSQL, -1, &insertStmt, nil) == SQLITE_OK)
        guard let insertStmt else { return }
        let transient = unsafeBitCast(OpaquePointer(bitPattern: -1)!, to: sqlite3_destructor_type.self)
        sqlite3_bind_text(insertStmt, 1, legacyID.uuidString, -1, transient)
        sqlite3_bind_double(insertStmt, 2, legacyTimestamp.timeIntervalSince1970)
        sqlite3_bind_int(insertStmt, 3, legacyProcess.pid)
        sqlite3_bind_text(insertStmt, 4, legacyProcess.name, -1, transient)
        sqlite3_bind_text(insertStmt, 5, legacyProcess.executable, -1, transient)
        sqlite3_bind_text(insertStmt, 6, legacyProcess.commandLine, -1, transient)
        sqlite3_bind_int(insertStmt, 7, legacyProcess.ppid)
        sqlite3_bind_text(insertStmt, 8, legacyJSON, -1, transient)
        #expect(sqlite3_step(insertStmt) == SQLITE_DONE)
        sqlite3_finalize(insertStmt)
        #expect(sqlite3_exec(raw, "PRAGMA user_version = 5", nil, nil, nil) == SQLITE_OK)
        sqlite3_close(raw)

        // Opening installs schema v8. Until the explicit pre-producer recovery
        // boundary runs, exact mixed readers must still preserve the v5 row.
        let store = try EventStore(path: path)
        #expect(try await store.count() == 1)
        let mixedExact = try await store.exactEventSnapshot(id: legacyID)
        #expect(mixedExact.event?.id == legacyID)
        #expect(mixedExact.event?.timestamp == legacyTimestamp)
        #expect(mixedExact.event?.process.executable == legacyProcess.executable)
        #expect(mixedExact.event?.process.args == legacyProcess.args)

        let recovery = try await store.recoverJournalBeforeProducers(
            now: legacyTimestamp.addingTimeInterval(1)
        )
        #expect(recovery.sourceEvents == 1)
        #expect(recovery.migratedEvents == 1)
        #expect(recovery.rolledExpiredEvents == 0)
        #expect(recovery.corruptPreservedEvents == 0)
        #expect(recovery.remainingEvents == 0)
        #expect(recovery.complete)

        #expect(try await store.count() == 1)
        let journalExact = try await store.exactEventSnapshot(id: legacyID)
        #expect(journalExact.event?.id == legacyID)
        #expect(journalExact.event?.timestamp == legacyTimestamp)
        #expect(journalExact.event?.process.executable == legacyProcess.executable)
        #expect(journalExact.event?.process.args == legacyProcess.args)

        // v8 recovery must finish with one authenticated journal event and no
        // quarantine or unaccounted source row.
        var verifyDB: OpaquePointer?
        defer { if let d = verifyDB { sqlite3_close(d) } }
        sqlite3_open_v2(path, &verifyDB, SQLITE_OPEN_READONLY, nil)
        guard let v = verifyDB else { return }
        #expect(Self.userVersion(of: v) == 8)
        #expect(Self.scalarInt(v, "SELECT count(*) FROM event_journal_blocks") == 1)
        #expect(Self.scalarInt(v, "SELECT count(*) FROM event_journal_legacy_quarantine") == 0)
        #expect(Self.scalarInt(v, """
            SELECT count(*) FROM event_journal_migration
            WHERE stage = 2 AND source_events = 1 AND migrated_events = 1
              AND rolled_expired_events = 0 AND corrupt_preserved_events = 0
              AND remaining_events = 0 AND schema_finalized = 1
            """) == 1)
    }

    @Test("Migration chain is idempotent — re-opening preserves user_version=8")
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
        #expect(Self.userVersion(of: db) == 8)
    }

    @Test("Finalized journal reopen bypasses transition-only pinned-WAL gate")
    func finalizedJournalReopensWithPinnedWAL() async throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("finalized-journal-reopen-\(UUID().uuidString)")
        try FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: true
        )
        defer { try? FileManager.default.removeItem(at: directory) }
        let path = directory.appendingPathComponent("events.db").path
        let policy = SQLitePersistentStorePolicy(
            maxFootprintBytes: 256 * SQLitePersistentStorePolicy.bytesPerMiB,
            freeSpaceFloorBytes: 0,
            transactionReserveBytes:
                SQLitePersistentStorePolicy.eventTransactionReserveBytes,
            storageVolumePath: directory.path
        )

        var bootstrap: EventStore? = try EventStore(
            path: path,
            storagePolicy: policy
        )
        _ = try await bootstrap?.recoverJournalBeforeProducers()
        #expect(await bootstrap?.walCheckpointTruncate() == true)

        var reader: OpaquePointer?
        #expect(sqlite3_open_v2(
            path,
            &reader,
            SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX,
            nil
        ) == SQLITE_OK)
        let readerHandle = try #require(reader)
        defer {
            if let reader { sqlite3_close(reader) }
        }
        #expect(sqlite3_exec(
            readerHandle,
            "BEGIN",
            nil,
            nil,
            nil
        ) == SQLITE_OK)
        defer {
            if let reader {
                sqlite3_exec(reader, "ROLLBACK", nil, nil, nil)
            }
        }
        var pinnedStatement: OpaquePointer?
        #expect(sqlite3_prepare_v2(
            readerHandle,
            "SELECT COUNT(*) FROM event_journal_blocks",
            -1,
            &pinnedStatement,
            nil
        ) == SQLITE_OK)
        let pinnedHandle = try #require(pinnedStatement)
        defer {
            if let pinnedStatement { sqlite3_finalize(pinnedStatement) }
        }
        #expect(sqlite3_step(pinnedHandle) == SQLITE_ROW)

        try await bootstrap?.insert(event: Self.makeEvent(
            process: Self.makeProcess()
        ))
        #expect(await bootstrap?.walCheckpointTruncate() == false)
        let walSize = (try FileManager.default.attributesOfItem(
            atPath: path + "-wal"
        )[.size] as? NSNumber)?.int64Value ?? 0
        #expect(walSize > 0)
        bootstrap = nil

        // schema_finalized=1 means no transition statement remains. The
        // active reader may pin those healthy WAL frames, but it must not turn
        // every daemon cold start into storage_not_ready.
        let reopened = try EventStore(path: path, storagePolicy: policy)
        let recovery = try await reopened.recoverJournalBeforeProducers()
        #expect(recovery.complete)
        // Startup immediately drains expired blocks after journal recovery.
        // A dashboard reader pinning the healthy retained WAL must defer that
        // routine retention sweep rather than crash-loop the system extension.
        #expect(try await reopened.expireJournalBlocks(
            retainedThrough: Date().addingTimeInterval(
                EventStore.journalRetentionSeconds + 1
            ),
            maximumBlocks: 1_024
        ) == 0)
        #expect(try await reopened.count() == 1)

        sqlite3_finalize(pinnedHandle)
        pinnedStatement = nil
        #expect(sqlite3_exec(
            readerHandle,
            "ROLLBACK",
            nil,
            nil,
            nil
        ) == SQLITE_OK)
        sqlite3_close(readerHandle)
        reader = nil
        #expect(try await reopened.expireJournalBlocks(
            retainedThrough: Date().addingTimeInterval(
                EventStore.journalRetentionSeconds + 1
            ),
            maximumBlocks: 1_024
        ) == 1)
        #expect(try await reopened.count() == 0)
    }

    @Test("Finalized marker cannot bypass an incomplete journal schema")
    func finalizedJournalInventoryStillFailsClosed() async throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("forged-finalized-journal-\(UUID().uuidString)")
        try FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: true
        )
        defer { try? FileManager.default.removeItem(at: directory) }
        let path = directory.appendingPathComponent("events.db").path

        var bootstrap: EventStore? = try EventStore(path: path)
        _ = try await bootstrap?.recoverJournalBeforeProducers()
        bootstrap = nil

        var raw: OpaquePointer?
        #expect(sqlite3_open_v2(
            path,
            &raw,
            SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX,
            nil
        ) == SQLITE_OK)
        let rawHandle = try #require(raw)
        #expect(sqlite3_exec(
            rawHandle,
            "DROP INDEX idx_event_projection_locator",
            nil,
            nil,
            nil
        ) == SQLITE_OK)
        sqlite3_close(rawHandle)
        raw = nil

        do {
            _ = try EventStore(path: path)
            Issue.record(
                "an incomplete schema with schema_finalized=1 unexpectedly reopened"
            )
        } catch EventStoreError.storageNotReady(let reason) {
            #expect(reason.contains(
                "missing index idx_event_projection_locator"
            ))
        }
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

        let read = try await store.exactEventsSnapshot(since: .distantPast)
        #expect(read.events.count == 1)
        guard let ev = read.events.first else { return }
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

        let read = try await store.exactEventsSnapshot(since: .distantPast)
        #expect(read.events.count == 1)
        // CommandSanitizer runs on insert; for a string of plain X's it
        // returns the input unchanged, so length must survive intact.
        #expect(read.events.first?.process.commandLine.count == 32_000)
    }
}
