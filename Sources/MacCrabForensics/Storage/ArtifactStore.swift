// ArtifactStore — the single writer for case-scoped artifacts.
//
// Plan reference: §3.4 schema, §3.8 audit Pass 2026-B (only this
// file may INSERT into `artifacts` / `artifact_data` /
// `plugin_invocations`) + audit Pass 2026-D (plaintext cases
// reject non-metadata classes at INSERT).
//
// Concurrency: actor-isolated. SQLite-level concurrency is single-
// writer-many-readers anyway; the actor makes the Swift surface
// match without bolting locks onto every entry point.

import Foundation
import CSQLCipher

/// Per-case SQLCipher store. One instance per open case; the
/// CaseManager (lands v1.13a-1.5) owns lifecycle. The store does
/// NOT own the case's vault/ or snapshots/ subdirectories — those
/// are CaseManager territory.
public actor ArtifactStore {

    private var db: OpaquePointer?
    private let path: String
    private let encryptionState: CaseEncryptionState

    /// Process-wide lock serializing the SQLite open + PRAGMA key
    /// + initial schema migration window. SQLCipher's
    /// `sqlcipher_extra_init` + `PRAGMA key` sequence is sensitive
    /// to concurrent open() calls — under parallel test runs we
    /// observed sporadic SQLITE_MISUSE (21) on subsequent
    /// prepare() calls. Serializing the init window resolves the
    /// race; once the connection is fully opened + keyed + migrated,
    /// SQLITE_OPEN_FULLMUTEX handles per-connection thread safety
    /// for normal usage.
    private static let initLock = NSLock()

    /// Open / create the per-case store. If `dek` is supplied,
    /// applies `PRAGMA key` BEFORE any other PRAGMA. SQLCipher
    /// requires the key be set before reads of the encrypted
    /// header.
    public init(
        path: String,
        dek: Data?,
        encryptionState: CaseEncryptionState
    ) async throws {
        self.path = path
        self.encryptionState = encryptionState

        // Acquire the process-wide init lock and hold it through
        // the entire open + key + migrate window.
        Self.initLock.lock()
        defer { Self.initLock.unlock() }

        var handle: OpaquePointer?
        let rc = sqlite3_open_v2(
            path,
            &handle,
            SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
            nil
        )
        guard rc == SQLITE_OK, let h = handle else {
            let msg = handle.map { String(cString: sqlite3_errmsg($0)) } ?? "sqlite3_open returned \(rc)"
            if let h = handle { sqlite3_close(h) }
            throw ArtifactStoreError.openFailed(message: msg, code: rc)
        }
        self.db = h

        // Apply DEK FIRST. SQLCipher's `PRAGMA key` must precede
        // any actual file read; otherwise the encrypted header
        // looks like a corrupt SQLite file and subsequent PRAGMAs
        // fail.
        if let dek = dek {
            try Self.applyDEK(handle: h, dek: dek)
        }

        // Then the operational PRAGMAs.
        for pragma in SchemaV1.openPragmas {
            let rcP = sqlite3_exec(h, pragma, nil, nil, nil)
            // PRAGMAs are advisory at this stage. If
            // journal_mode=WAL is rejected we still proceed.
            if rcP != SQLITE_OK {
                // Log via OSLog in a follow-up commit; for now,
                // silent. Error path is exercised by tests.
                _ = rcP
            }
        }

        // Schema migration.
        try Self.migrate(handle: h)
    }

    deinit {
        if let h = db { sqlite3_close(h) }
    }

    // MARK: - PRAGMA key (SQLCipher unlock)

    private static func applyDEK(handle: OpaquePointer, dek: Data) throws {
        // SQLCipher accepts `PRAGMA key = "x'<hex>'"` for raw
        // bytes (no KDF run). We always feed a 32-byte key so
        // SQLCipher uses it directly (matches SQLCipher's
        // "raw key" mode). Keys derived via login-keychain wrap
        // arrive at 32 bytes; the CaseManager (v1.13a-1.5)
        // enforces.
        let hex = dek.map { String(format: "%02x", $0) }.joined()
        let stmt = "PRAGMA key = \"x'\(hex)'\""
        var err: UnsafeMutablePointer<CChar>?
        let rc = sqlite3_exec(handle, stmt, nil, nil, &err)
        if rc != SQLITE_OK {
            let msg = err.map { String(cString: $0) } ?? "PRAGMA key failed (\(rc))"
            if let err = err { sqlite3_free(err) }
            throw ArtifactStoreError.keyApplicationFailed(message: msg)
        }
        if let err = err { sqlite3_free(err) }

        // Verify the key unlocked the file by reading the schema
        // cookie. SQLCipher returns SQLITE_NOTADB if the key is
        // wrong.
        var verifyStmt: OpaquePointer?
        let prep = sqlite3_prepare_v2(handle, "SELECT count(*) FROM sqlite_master", -1, &verifyStmt, nil)
        defer { sqlite3_finalize(verifyStmt) }
        if prep != SQLITE_OK {
            let msg = String(cString: sqlite3_errmsg(handle))
            throw ArtifactStoreError.keyApplicationFailed(message: "verify prepare failed: \(msg)")
        }
        let step = sqlite3_step(verifyStmt)
        if step != SQLITE_ROW {
            let msg = String(cString: sqlite3_errmsg(handle))
            throw ArtifactStoreError.keyApplicationFailed(message: "verify step failed: \(msg)")
        }
    }

    // MARK: - Migrations

    private static func migrate(handle: OpaquePointer) throws {
        var currentVersion: Int32 = 0
        var stmt: OpaquePointer?
        let p = sqlite3_prepare_v2(handle, "PRAGMA user_version", -1, &stmt, nil)
        if p == SQLITE_OK {
            if sqlite3_step(stmt) == SQLITE_ROW {
                currentVersion = sqlite3_column_int(stmt, 0)
            }
        }
        sqlite3_finalize(stmt)

        if currentVersion < SchemaV1.userVersion {
            let rc = sqlite3_exec(handle, SchemaV1.createDDL, nil, nil, nil)
            if rc != SQLITE_OK {
                let msg = String(cString: sqlite3_errmsg(handle))
                throw ArtifactStoreError.migrationFailed(
                    fromVersion: Int(currentVersion),
                    toVersion: Int(SchemaV1.userVersion),
                    message: msg
                )
            }
            let bump = "PRAGMA user_version = \(SchemaV1.userVersion)"
            sqlite3_exec(handle, bump, nil, nil, nil)
        }
    }

    // MARK: - Cases

    /// INSERT a new case record. Idempotent on `cases.id` — calling
    /// twice with the same id is a no-op (silently accepted).
    public func insertCase(_ row: CaseRecord) throws {
        guard let db = db else { return }
        let sql = """
            INSERT OR IGNORE INTO cases (
                id, name, created_at, time_window_start, time_window_end,
                notes, encryption_state, ai_content_allowed, scheduled_trusted
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """
        var stmt: OpaquePointer?
        let p = sqlite3_prepare_v2(db, sql, -1, &stmt, nil)
        defer { sqlite3_finalize(stmt) }
        guard p == SQLITE_OK else {
            throw ArtifactStoreError.stepFailed(
                operation: "insertCase prepare",
                message: String(cString: sqlite3_errmsg(db)),
                code: p
            )
        }
        sqlite3_bind_text(stmt, 1, row.id, -1, SQLITE_TRANSIENT)
        sqlite3_bind_text(stmt, 2, row.name, -1, SQLITE_TRANSIENT)
        sqlite3_bind_int64(stmt, 3, Int64(row.createdAt.timeIntervalSince1970 * 1000))
        if let s = row.timeWindowStart {
            sqlite3_bind_int64(stmt, 4, Int64(s.timeIntervalSince1970 * 1000))
        } else {
            sqlite3_bind_null(stmt, 4)
        }
        if let e = row.timeWindowEnd {
            sqlite3_bind_int64(stmt, 5, Int64(e.timeIntervalSince1970 * 1000))
        } else {
            sqlite3_bind_null(stmt, 5)
        }
        if let n = row.notes {
            sqlite3_bind_text(stmt, 6, n, -1, SQLITE_TRANSIENT)
        } else {
            sqlite3_bind_null(stmt, 6)
        }
        sqlite3_bind_text(stmt, 7, row.encryptionState.rawValue, -1, SQLITE_TRANSIENT)
        sqlite3_bind_int(stmt, 8, row.aiContentAllowed ? 1 : 0)
        sqlite3_bind_int(stmt, 9, row.scheduledTrusted ? 1 : 0)
        let step = sqlite3_step(stmt)
        guard step == SQLITE_DONE else {
            throw ArtifactStoreError.stepFailed(
                operation: "insertCase step",
                message: String(cString: sqlite3_errmsg(db)),
                code: step
            )
        }
    }

    /// Look up a single case by id. Returns nil if absent.
    public func fetchCase(id: String) throws -> CaseRecord? {
        guard let db = db else { return nil }
        let sql = """
            SELECT id, name, created_at, time_window_start, time_window_end,
                   notes, encryption_state, ai_content_allowed, scheduled_trusted
            FROM cases WHERE id = ?
            """
        var stmt: OpaquePointer?
        let p = sqlite3_prepare_v2(db, sql, -1, &stmt, nil)
        defer { sqlite3_finalize(stmt) }
        guard p == SQLITE_OK else {
            throw ArtifactStoreError.stepFailed(
                operation: "fetchCase prepare",
                message: String(cString: sqlite3_errmsg(db)),
                code: p
            )
        }
        sqlite3_bind_text(stmt, 1, id, -1, SQLITE_TRANSIENT)
        guard sqlite3_step(stmt) == SQLITE_ROW else {
            return nil
        }
        return try Self.readCaseRow(stmt: stmt!)
    }

    /// List every case in this store. Used by `maccrabctl case list`.
    /// In v1.13a-1 there's one store per case so this returns at
    /// most one row — but the API shape stays plural for the
    /// future Cases/ registry that aggregates across cases.
    public func listCases() throws -> [CaseRecord] {
        guard let db = db else { return [] }
        let sql = """
            SELECT id, name, created_at, time_window_start, time_window_end,
                   notes, encryption_state, ai_content_allowed, scheduled_trusted
            FROM cases ORDER BY created_at DESC
            """
        var stmt: OpaquePointer?
        let p = sqlite3_prepare_v2(db, sql, -1, &stmt, nil)
        defer { sqlite3_finalize(stmt) }
        guard p == SQLITE_OK else {
            throw ArtifactStoreError.stepFailed(
                operation: "listCases prepare",
                message: String(cString: sqlite3_errmsg(db)),
                code: p
            )
        }
        var out: [CaseRecord] = []
        while sqlite3_step(stmt) == SQLITE_ROW {
            out.append(try Self.readCaseRow(stmt: stmt!))
        }
        return out
    }

    /// Flip per-case AI grant. Used by
    /// `maccrabctl case allow-ai --content <id>`.
    public func setAIContentAllowed(caseID: String, allowed: Bool) throws {
        guard let db = db else { return }
        let sql = "UPDATE cases SET ai_content_allowed = ? WHERE id = ?"
        var stmt: OpaquePointer?
        let p = sqlite3_prepare_v2(db, sql, -1, &stmt, nil)
        defer { sqlite3_finalize(stmt) }
        guard p == SQLITE_OK else {
            throw ArtifactStoreError.stepFailed(
                operation: "setAIContentAllowed prepare",
                message: String(cString: sqlite3_errmsg(db)),
                code: p
            )
        }
        sqlite3_bind_int(stmt, 1, allowed ? 1 : 0)
        sqlite3_bind_text(stmt, 2, caseID, -1, SQLITE_TRANSIENT)
        let step = sqlite3_step(stmt)
        guard step == SQLITE_DONE else {
            throw ArtifactStoreError.stepFailed(
                operation: "setAIContentAllowed step",
                message: String(cString: sqlite3_errmsg(db)),
                code: step
            )
        }
    }

    /// Flip per-case scheduled-trusted opt-in. Used by
    /// `maccrabctl case mark-trusted-scheduled <id>`.
    public func setScheduledTrusted(caseID: String, trusted: Bool) throws {
        guard let db = db else { return }
        let sql = "UPDATE cases SET scheduled_trusted = ? WHERE id = ?"
        var stmt: OpaquePointer?
        let p = sqlite3_prepare_v2(db, sql, -1, &stmt, nil)
        defer { sqlite3_finalize(stmt) }
        guard p == SQLITE_OK else {
            throw ArtifactStoreError.stepFailed(
                operation: "setScheduledTrusted prepare",
                message: String(cString: sqlite3_errmsg(db)),
                code: p
            )
        }
        sqlite3_bind_int(stmt, 1, trusted ? 1 : 0)
        sqlite3_bind_text(stmt, 2, caseID, -1, SQLITE_TRANSIENT)
        let step = sqlite3_step(stmt)
        guard step == SQLITE_DONE else {
            throw ArtifactStoreError.stepFailed(
                operation: "setScheduledTrusted step",
                message: String(cString: sqlite3_errmsg(db)),
                code: step
            )
        }
    }

    // MARK: - Artifacts

    /// **The only public path that INSERTs into `artifacts` /
    /// `artifact_data`.** Audit Pass 2026-B enforces by scanning
    /// for INSERT statements against those tables outside this
    /// file.
    ///
    /// Returns the assigned artifact id.
    @discardableResult
    public func commit(_ record: ArtifactRecord) throws -> Int64 {
        // Pass 2026-D: plaintext cases reject non-metadata at INSERT.
        if encryptionState == .plaintext, record.privacyClass != .metadata {
            throw ArtifactStoreError.plaintextCaseRejectsNonMetadata(
                contentType: record.contentType,
                privacyClass: record.privacyClass
            )
        }
        guard let db = db else {
            throw ArtifactStoreError.stepFailed(
                operation: "commit",
                message: "db handle closed",
                code: SQLITE_MISUSE
            )
        }

        let json = try Self.encodeJSON(record.data)

        // Wrap the two INSERTs in a savepoint so artifact + payload
        // commit atomically. SAVEPOINT vs BEGIN/COMMIT so it nests
        // correctly under a future write-batching transaction.
        let savepointName = "commit_artifact"
        sqlite3_exec(db, "SAVEPOINT \(savepointName)", nil, nil, nil)

        var rolledBack = false
        defer {
            if rolledBack {
                sqlite3_exec(db, "ROLLBACK TO SAVEPOINT \(savepointName)", nil, nil, nil)
                sqlite3_exec(db, "RELEASE SAVEPOINT \(savepointName)", nil, nil, nil)
            } else {
                sqlite3_exec(db, "RELEASE SAVEPOINT \(savepointName)", nil, nil, nil)
            }
        }

        let insertArtifact = """
            INSERT INTO artifacts (
                case_id, plugin_id, plugin_version, schema_version,
                content_type, source_path, source_inode, source_mtime,
                sha256, blob_relpath, observed_at, captured_at,
                summary, size_bytes, confidence, privacy_class, actor
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """
        var aStmt: OpaquePointer?
        let pA = sqlite3_prepare_v2(db, insertArtifact, -1, &aStmt, nil)
        defer { sqlite3_finalize(aStmt) }
        guard pA == SQLITE_OK else {
            rolledBack = true
            throw ArtifactStoreError.stepFailed(
                operation: "commit prepare artifact",
                message: String(cString: sqlite3_errmsg(db)),
                code: pA
            )
        }
        sqlite3_bind_text(aStmt, 1, record.caseID, -1, SQLITE_TRANSIENT)
        sqlite3_bind_text(aStmt, 2, record.pluginID, -1, SQLITE_TRANSIENT)
        sqlite3_bind_text(aStmt, 3, record.pluginVersion, -1, SQLITE_TRANSIENT)
        sqlite3_bind_int(aStmt, 4, Int32(record.schemaVersion))
        sqlite3_bind_text(aStmt, 5, record.contentType, -1, SQLITE_TRANSIENT)
        if let sp = record.sourcePath {
            sqlite3_bind_text(aStmt, 6, sp, -1, SQLITE_TRANSIENT)
        } else {
            sqlite3_bind_null(aStmt, 6)
        }
        if let si = record.sourceInode {
            sqlite3_bind_int64(aStmt, 7, Int64(bitPattern: UInt64(si)))
        } else {
            sqlite3_bind_null(aStmt, 7)
        }
        if let sm = record.sourceMtime {
            sqlite3_bind_int64(aStmt, 8, sm)
        } else {
            sqlite3_bind_null(aStmt, 8)
        }
        sqlite3_bind_text(aStmt, 9, record.sha256, -1, SQLITE_TRANSIENT)
        if let br = record.blobRelpath {
            sqlite3_bind_text(aStmt, 10, br, -1, SQLITE_TRANSIENT)
        } else {
            sqlite3_bind_null(aStmt, 10)
        }
        sqlite3_bind_int64(aStmt, 11, Int64(record.observedAt.timeIntervalSince1970 * 1000))
        sqlite3_bind_int64(aStmt, 12, Int64(record.capturedAt.timeIntervalSince1970 * 1000))
        if let s = record.summary {
            sqlite3_bind_text(aStmt, 13, s, -1, SQLITE_TRANSIENT)
        } else {
            sqlite3_bind_null(aStmt, 13)
        }
        sqlite3_bind_int64(aStmt, 14, record.sizeBytes)
        sqlite3_bind_text(aStmt, 15, record.confidence.rawValue, -1, SQLITE_TRANSIENT)
        sqlite3_bind_text(aStmt, 16, record.privacyClass.rawValue, -1, SQLITE_TRANSIENT)
        if let a = record.actor {
            sqlite3_bind_text(aStmt, 17, a, -1, SQLITE_TRANSIENT)
        } else {
            sqlite3_bind_null(aStmt, 17)
        }
        let stepA = sqlite3_step(aStmt)
        guard stepA == SQLITE_DONE else {
            rolledBack = true
            throw ArtifactStoreError.stepFailed(
                operation: "commit step artifact",
                message: String(cString: sqlite3_errmsg(db)),
                code: stepA
            )
        }
        let artifactID = sqlite3_last_insert_rowid(db)

        let insertData = "INSERT INTO artifact_data (artifact_id, json) VALUES (?, ?)"
        var dStmt: OpaquePointer?
        let pD = sqlite3_prepare_v2(db, insertData, -1, &dStmt, nil)
        defer { sqlite3_finalize(dStmt) }
        guard pD == SQLITE_OK else {
            rolledBack = true
            throw ArtifactStoreError.stepFailed(
                operation: "commit prepare data",
                message: String(cString: sqlite3_errmsg(db)),
                code: pD
            )
        }
        sqlite3_bind_int64(dStmt, 1, artifactID)
        sqlite3_bind_text(dStmt, 2, json, -1, SQLITE_TRANSIENT)
        let stepD = sqlite3_step(dStmt)
        guard stepD == SQLITE_DONE else {
            rolledBack = true
            throw ArtifactStoreError.stepFailed(
                operation: "commit step data",
                message: String(cString: sqlite3_errmsg(db)),
                code: stepD
            )
        }

        return artifactID
    }

    /// Read-side: paginated query against committed artifacts.
    public func query(_ q: ArtifactQuery) throws -> [CommittedArtifact] {
        guard let db = db else { return [] }

        var conditions: [String] = ["a.case_id = ?"]
        if q.contentType != nil { conditions.append("a.content_type = ?") }
        if q.observedAfter != nil { conditions.append("a.observed_at >= ?") }
        if q.observedBefore != nil { conditions.append("a.observed_at <= ?") }
        if let pc = q.privacyClassAtMost {
            // Implementation: use a CASE expression on the rawValue
            // ordering. metadata < content < personalComms <
            // credentialAdjacent < secret.
            conditions.append("CASE a.privacy_class " +
                "WHEN 'metadata' THEN 0 " +
                "WHEN 'content' THEN 1 " +
                "WHEN 'personalComms' THEN 2 " +
                "WHEN 'credentialAdjacent' THEN 3 " +
                "WHEN 'secret' THEN 4 ELSE 5 END <= \(Self.classRank(pc))")
        }

        let whereClause = conditions.joined(separator: " AND ")
        let sql = """
            SELECT a.id, a.case_id, a.plugin_id, a.plugin_version,
                   a.schema_version, a.content_type, a.source_path,
                   a.source_inode, a.source_mtime, a.sha256,
                   a.blob_relpath, a.observed_at, a.captured_at,
                   a.summary, a.size_bytes, a.confidence,
                   a.privacy_class, a.actor, d.json
            FROM artifacts a
            JOIN artifact_data d ON d.artifact_id = a.id
            WHERE \(whereClause)
            ORDER BY a.observed_at DESC
            LIMIT ? OFFSET ?
            """
        var stmt: OpaquePointer?
        let p = sqlite3_prepare_v2(db, sql, -1, &stmt, nil)
        defer { sqlite3_finalize(stmt) }
        guard p == SQLITE_OK else {
            throw ArtifactStoreError.stepFailed(
                operation: "query prepare",
                message: String(cString: sqlite3_errmsg(db)),
                code: p
            )
        }

        var idx: Int32 = 1
        sqlite3_bind_text(stmt, idx, q.caseID, -1, SQLITE_TRANSIENT); idx += 1
        if let ct = q.contentType {
            sqlite3_bind_text(stmt, idx, ct, -1, SQLITE_TRANSIENT); idx += 1
        }
        if let oa = q.observedAfter {
            sqlite3_bind_int64(stmt, idx, Int64(oa.timeIntervalSince1970 * 1000)); idx += 1
        }
        if let ob = q.observedBefore {
            sqlite3_bind_int64(stmt, idx, Int64(ob.timeIntervalSince1970 * 1000)); idx += 1
        }
        sqlite3_bind_int(stmt, idx, Int32(q.limit)); idx += 1
        sqlite3_bind_int(stmt, idx, Int32(q.offset))

        var out: [CommittedArtifact] = []
        while sqlite3_step(stmt) == SQLITE_ROW {
            out.append(try Self.readArtifactRow(stmt: stmt!))
        }
        return out
    }

    /// rc.15 — content-type counts for a case, used by the scan
    /// detail view's sidebar so we don't have to load every
    /// artifact upfront just to know the grouping. SQL COUNT +
    /// GROUP BY is sub-millisecond even for 10K+ row cases.
    public func contentTypeCounts(caseID: String) throws -> [(contentType: String, count: Int)] {
        guard let db = db else { return [] }
        let sql = "SELECT content_type, COUNT(*) FROM artifacts WHERE case_id = ? GROUP BY content_type ORDER BY content_type"
        var stmt: OpaquePointer?
        let p = sqlite3_prepare_v2(db, sql, -1, &stmt, nil)
        defer { sqlite3_finalize(stmt) }
        guard p == SQLITE_OK else { return [] }
        sqlite3_bind_text(stmt, 1, caseID, -1, SQLITE_TRANSIENT)
        var out: [(String, Int)] = []
        while sqlite3_step(stmt) == SQLITE_ROW {
            let ct = String(cString: sqlite3_column_text(stmt, 0))
            let c = Int(sqlite3_column_int64(stmt, 1))
            out.append((ct, c))
        }
        return out
    }

    /// Cheap COUNT(*) for live progress UI — used by the kit
    /// runner's poll loop while a collector is mid-flight to show
    /// "X rows so far". Sub-millisecond on indexed case_id.
    public func count(caseID: String, pluginID: String? = nil) throws -> Int {
        guard let db = db else { return 0 }
        let sql: String
        if pluginID != nil {
            sql = "SELECT COUNT(*) FROM artifacts WHERE case_id = ? AND plugin_id = ?"
        } else {
            sql = "SELECT COUNT(*) FROM artifacts WHERE case_id = ?"
        }
        var stmt: OpaquePointer?
        let p = sqlite3_prepare_v2(db, sql, -1, &stmt, nil)
        defer { sqlite3_finalize(stmt) }
        guard p == SQLITE_OK else {
            throw ArtifactStoreError.stepFailed(
                operation: "count prepare",
                message: String(cString: sqlite3_errmsg(db)),
                code: p
            )
        }
        sqlite3_bind_text(stmt, 1, caseID, -1, SQLITE_TRANSIENT)
        if let pid = pluginID {
            sqlite3_bind_text(stmt, 2, pid, -1, SQLITE_TRANSIENT)
        }
        guard sqlite3_step(stmt) == SQLITE_ROW else { return 0 }
        return Int(sqlite3_column_int64(stmt, 0))
    }

    // MARK: - Invocations

    /// Open a `plugin_invocations` row. Returns the assigned id;
    /// `recordInvocationEnd` closes it.
    @discardableResult
    public func recordInvocationStart(
        caseID: String,
        pluginID: String,
        pluginVersion: String,
        inputsJSON: String,
        startedAt: Date = Date()
    ) throws -> Int64 {
        guard let db = db else {
            throw ArtifactStoreError.stepFailed(
                operation: "recordInvocationStart",
                message: "db handle closed",
                code: SQLITE_MISUSE
            )
        }
        let sql = """
            INSERT INTO plugin_invocations (
                case_id, plugin_id, plugin_version, inputs_json,
                started_at, exit_status
            ) VALUES (?, ?, ?, ?, ?, 'running')
            """
        var stmt: OpaquePointer?
        let p = sqlite3_prepare_v2(db, sql, -1, &stmt, nil)
        defer { sqlite3_finalize(stmt) }
        guard p == SQLITE_OK else {
            throw ArtifactStoreError.stepFailed(
                operation: "recordInvocationStart prepare",
                message: String(cString: sqlite3_errmsg(db)),
                code: p
            )
        }
        sqlite3_bind_text(stmt, 1, caseID, -1, SQLITE_TRANSIENT)
        sqlite3_bind_text(stmt, 2, pluginID, -1, SQLITE_TRANSIENT)
        sqlite3_bind_text(stmt, 3, pluginVersion, -1, SQLITE_TRANSIENT)
        sqlite3_bind_text(stmt, 4, inputsJSON, -1, SQLITE_TRANSIENT)
        sqlite3_bind_int64(stmt, 5, Int64(startedAt.timeIntervalSince1970 * 1000))
        let step = sqlite3_step(stmt)
        guard step == SQLITE_DONE else {
            throw ArtifactStoreError.stepFailed(
                operation: "recordInvocationStart step",
                message: String(cString: sqlite3_errmsg(db)),
                code: step
            )
        }
        return sqlite3_last_insert_rowid(db)
    }

    /// Close out an invocation with final counts + exit status.
    public func recordInvocationEnd(
        id: Int64,
        exitStatus: String,
        artifactsCommitted: Int64,
        artifactsRejected: Int64,
        errorMessage: String?,
        snapshotHash: String?,
        completedAt: Date = Date()
    ) throws {
        guard let db = db else { return }
        let sql = """
            UPDATE plugin_invocations
            SET completed_at = ?, exit_status = ?,
                artifacts_committed = ?, artifacts_rejected = ?,
                error_message = ?, snapshot_hash = ?
            WHERE id = ?
            """
        var stmt: OpaquePointer?
        let p = sqlite3_prepare_v2(db, sql, -1, &stmt, nil)
        defer { sqlite3_finalize(stmt) }
        guard p == SQLITE_OK else {
            throw ArtifactStoreError.stepFailed(
                operation: "recordInvocationEnd prepare",
                message: String(cString: sqlite3_errmsg(db)),
                code: p
            )
        }
        sqlite3_bind_int64(stmt, 1, Int64(completedAt.timeIntervalSince1970 * 1000))
        sqlite3_bind_text(stmt, 2, exitStatus, -1, SQLITE_TRANSIENT)
        sqlite3_bind_int64(stmt, 3, artifactsCommitted)
        sqlite3_bind_int64(stmt, 4, artifactsRejected)
        if let em = errorMessage {
            sqlite3_bind_text(stmt, 5, em, -1, SQLITE_TRANSIENT)
        } else {
            sqlite3_bind_null(stmt, 5)
        }
        if let sh = snapshotHash {
            sqlite3_bind_text(stmt, 6, sh, -1, SQLITE_TRANSIENT)
        } else {
            sqlite3_bind_null(stmt, 6)
        }
        sqlite3_bind_int64(stmt, 7, id)
        let step = sqlite3_step(stmt)
        guard step == SQLITE_DONE else {
            throw ArtifactStoreError.stepFailed(
                operation: "recordInvocationEnd step",
                message: String(cString: sqlite3_errmsg(db)),
                code: step
            )
        }
    }

    // MARK: - Read helpers

    private static func readCaseRow(stmt: OpaquePointer) throws -> CaseRecord {
        let id = String(cString: sqlite3_column_text(stmt, 0))
        let name = String(cString: sqlite3_column_text(stmt, 1))
        let createdAtMS = sqlite3_column_int64(stmt, 2)
        let twStartMS: Int64? = sqlite3_column_type(stmt, 3) == SQLITE_NULL ? nil : sqlite3_column_int64(stmt, 3)
        let twEndMS: Int64? = sqlite3_column_type(stmt, 4) == SQLITE_NULL ? nil : sqlite3_column_int64(stmt, 4)
        let notes: String? = sqlite3_column_type(stmt, 5) == SQLITE_NULL ? nil : String(cString: sqlite3_column_text(stmt, 5))
        let encStateRaw = String(cString: sqlite3_column_text(stmt, 6))
        let aiAllowed = sqlite3_column_int(stmt, 7) != 0
        let schedTrusted = sqlite3_column_int(stmt, 8) != 0
        guard let encState = CaseEncryptionState(rawValue: encStateRaw) else {
            throw ArtifactStoreError.stepFailed(
                operation: "readCaseRow",
                message: "unknown encryption_state '\(encStateRaw)'",
                code: SQLITE_ERROR
            )
        }
        return CaseRecord(
            id: id,
            name: name,
            createdAt: Date(timeIntervalSince1970: Double(createdAtMS) / 1000),
            timeWindowStart: twStartMS.map { Date(timeIntervalSince1970: Double($0) / 1000) },
            timeWindowEnd: twEndMS.map { Date(timeIntervalSince1970: Double($0) / 1000) },
            notes: notes,
            encryptionState: encState,
            aiContentAllowed: aiAllowed,
            scheduledTrusted: schedTrusted
        )
    }

    private static func readArtifactRow(stmt: OpaquePointer) throws -> CommittedArtifact {
        let id = sqlite3_column_int64(stmt, 0)
        let caseID = String(cString: sqlite3_column_text(stmt, 1))
        let pluginID = String(cString: sqlite3_column_text(stmt, 2))
        let pluginVersion = String(cString: sqlite3_column_text(stmt, 3))
        let schemaVersion = Int(sqlite3_column_int(stmt, 4))
        let contentType = String(cString: sqlite3_column_text(stmt, 5))
        let sourcePath: String? = sqlite3_column_type(stmt, 6) == SQLITE_NULL ? nil : String(cString: sqlite3_column_text(stmt, 6))
        let sourceInode: UInt64? = sqlite3_column_type(stmt, 7) == SQLITE_NULL ? nil : UInt64(bitPattern: sqlite3_column_int64(stmt, 7))
        let sourceMtime: Int64? = sqlite3_column_type(stmt, 8) == SQLITE_NULL ? nil : sqlite3_column_int64(stmt, 8)
        let sha = String(cString: sqlite3_column_text(stmt, 9))
        let blobRel: String? = sqlite3_column_type(stmt, 10) == SQLITE_NULL ? nil : String(cString: sqlite3_column_text(stmt, 10))
        let observedAtMS = sqlite3_column_int64(stmt, 11)
        let capturedAtMS = sqlite3_column_int64(stmt, 12)
        let summary: String? = sqlite3_column_type(stmt, 13) == SQLITE_NULL ? nil : String(cString: sqlite3_column_text(stmt, 13))
        let sizeBytes = sqlite3_column_int64(stmt, 14)
        let confRaw = String(cString: sqlite3_column_text(stmt, 15))
        let pcRaw = String(cString: sqlite3_column_text(stmt, 16))
        let actor: String? = sqlite3_column_type(stmt, 17) == SQLITE_NULL ? nil : String(cString: sqlite3_column_text(stmt, 17))
        let jsonText = String(cString: sqlite3_column_text(stmt, 18))

        guard let conf = Confidence(rawValue: confRaw) else {
            throw ArtifactStoreError.stepFailed(
                operation: "readArtifactRow",
                message: "unknown confidence '\(confRaw)'",
                code: SQLITE_ERROR
            )
        }
        guard let pc = PrivacyClass(rawValue: pcRaw) else {
            throw ArtifactStoreError.stepFailed(
                operation: "readArtifactRow",
                message: "unknown privacy_class '\(pcRaw)'",
                code: SQLITE_ERROR
            )
        }
        let dataDict: [String: JSONValue]
        if let jsonData = jsonText.data(using: .utf8) {
            dataDict = (try? JSONDecoder().decode([String: JSONValue].self, from: jsonData)) ?? [:]
        } else {
            dataDict = [:]
        }

        let rec = ArtifactRecord(
            caseID: caseID,
            pluginID: pluginID,
            pluginVersion: pluginVersion,
            schemaVersion: schemaVersion,
            contentType: contentType,
            sourcePath: sourcePath,
            sourceInode: sourceInode,
            sourceMtime: sourceMtime,
            sha256: sha,
            blobRelpath: blobRel,
            observedAt: Date(timeIntervalSince1970: Double(observedAtMS) / 1000),
            capturedAt: Date(timeIntervalSince1970: Double(capturedAtMS) / 1000),
            summary: summary,
            sizeBytes: sizeBytes,
            confidence: conf,
            privacyClass: pc,
            actor: actor,
            data: dataDict
        )
        return CommittedArtifact(id: id, record: rec)
    }

    private static func encodeJSON(_ dict: [String: JSONValue]) throws -> String {
        do {
            let data = try JSONEncoder().encode(dict)
            return String(data: data, encoding: .utf8) ?? "{}"
        } catch {
            throw ArtifactStoreError.jsonSerializationFailed(
                message: error.localizedDescription
            )
        }
    }

    private static func classRank(_ c: PrivacyClass) -> Int {
        switch c {
        case .metadata: return 0
        case .content: return 1
        case .personalComms: return 2
        case .credentialAdjacent: return 3
        case .secret: return 4
        }
    }
}

// MARK: - SQLite binding constants

// SQLite expects an SQLITE_TRANSIENT pointer (-1 as a void *) when
// asked to copy the supplied string into its own storage. The
// constant isn't exposed on the Swift module map by default.
private let SQLITE_TRANSIENT = unsafeBitCast(
    OpaquePointer(bitPattern: -1)!,
    to: sqlite3_destructor_type.self
)
