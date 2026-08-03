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
import MacCrabCore

/// Per-case SQLCipher store. One instance per open case; the
/// CaseManager (lands v1.13a-1.5) owns lifecycle. The store does
/// NOT own the case's vault/ or snapshots/ subdirectories — those
/// are CaseManager territory.
public actor ArtifactStore {

    private var db: OpaquePointer?
    private var checkpointController: SQLiteControlledCheckpointController?
    private let path: String
    private let encryptionState: CaseEncryptionState
    private let storagePolicy: SQLitePersistentStorePolicy
    private var storageAdmission: SQLitePersistentStoreAdmission
    /// Authoritative SQLCipher page size read after the key is applied. Row
    /// estimates charge dirty leaf/tree pages at this value rather than
    /// assuming that every legacy case uses SQLite's current default.
    private let sqlitePageSizeBytes: Int64
    /// Existing databases may open read/shed-only while over cap or below the
    /// free-space floor. In that state the open PRAGMAs and migrations are
    /// intentionally skipped; the first later-admitted writer must complete
    /// them before it is allowed to prepare application SQL.
    private var initializationPending: Bool

    /// Open / create the per-case store. If `dek` is supplied,
    /// applies `PRAGMA key` BEFORE any other PRAGMA. SQLCipher
    /// requires the key be set before reads of the encrypted
    /// header.
    public init(
        path: String,
        dek: Data?,
        encryptionState: CaseEncryptionState,
        storagePolicy suppliedPolicy: SQLitePersistentStorePolicy? = nil
    ) async throws {
        self.path = path
        self.encryptionState = encryptionState
        let policy = suppliedPolicy ?? Self.defaultStoragePolicy(for: path)
        self.storagePolicy = policy

        let expectsDEK = encryptionState != .plaintext
        guard expectsDEK == (dek != nil) else {
            throw ArtifactStoreError.encryptionStateMismatch(
                state: encryptionState,
                suppliedDEK: dek != nil
            )
        }

        // v1.21.5: the locked open + key + migrate window lives in a
        // synchronous static helper because NSLock.lock()/unlock()
        // are unavailable from async contexts in the Swift 6
        // language mode. The window has no suspension points, so the
        // serialization is byte-for-byte the same; keeping it in a
        // sync function also makes it impossible to later introduce
        // an `await` while the gate is held.
        let opened = try Self.openKeyedAndMigrated(
            path: path,
            dek: dek,
            storagePolicy: policy
        )
        self.db = opened.handle
        self.storageAdmission = opened.admission
        self.sqlitePageSizeBytes = opened.pageSizeBytes
        self.initializationPending = opened.initializationPending
        self.checkpointController = opened.checkpointController
    }

    /// Synchronous open + PRAGMA key + migrate window, held under
    /// the process-wide `initLock`. On failure the handle is closed
    /// here (still inside the gate) before the error propagates.
    private static func openKeyedAndMigrated(
        path: String,
        dek: Data?,
        storagePolicy: SQLitePersistentStorePolicy
    ) throws -> (
        handle: OpaquePointer,
        admission: SQLitePersistentStoreAdmission,
        pageSizeBytes: Int64,
        initializationPending: Bool,
        checkpointController: SQLiteControlledCheckpointController
    ) {
        // ArtifactStore and LiveDBSnapshot both link the same SQLCipher global
        // state. A private lock here did not serialize against snapshot opens,
        // despite CSQLCipherInitGate's contract, and recreated the parallel
        // SQLITE_MISUSE race whenever those two surfaces overlapped.
        return try CSQLCipherInitGate.withLock {
            try openKeyedAndMigratedUnderGate(
                path: path,
                dek: dek,
                storagePolicy: storagePolicy
            )
        }
    }

    private static func openKeyedAndMigratedUnderGate(
        path: String,
        dek: Data?,
        storagePolicy: SQLitePersistentStorePolicy
    ) throws -> (
        handle: OpaquePointer,
        admission: SQLitePersistentStoreAdmission,
        pageSizeBytes: Int64,
        initializationPending: Bool,
        checkpointController: SQLiteControlledCheckpointController
    ) {

        try validateSQLiteFamily(path: path)
        _ = try SQLitePersistentStoreAdmission.measureFamily(path)
        let existingDatabase = try SQLitePersistentStoreAdmission
            .mainFileExists(path)
        var admission = try SQLitePersistentStoreAdmission(
            databasePath: path,
            policy: storagePolicy,
            latchOperationalPressure: existingDatabase
        )

        var handle: OpaquePointer?
        let rc = SQLiteOpenPathPolicy.open(
            path,
            database: &handle,
            flags: SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE
                | SQLITE_OPEN_FULLMUTEX
        )
        guard rc == SQLITE_OK, let h = handle else {
            let msg = handle.map { String(cString: sqlite3_errmsg($0)) } ?? "sqlite3_open returned \(rc)"
            if let h = handle { sqlite3_close(h) }
            throw ArtifactStoreError.openFailed(message: msg, code: rc)
        }

        let checkpointController: SQLiteControlledCheckpointController
        do {
            checkpointController = try .install(
                on: h,
                thresholdPages: SQLiteControlledCheckpointController
                    .defaultThresholdPages,
                families: [
                    "main": SQLiteControlledCheckpointFamily(
                        databasePath: path,
                        policy: storagePolicy
                    ),
                ]
            )
        } catch {
            sqlite3_close(h)
            throw error
        }

        do {
            // Apply DEK FIRST. SQLCipher's `PRAGMA key` must precede
            // any actual file read; otherwise the encrypted header
            // looks like a corrupt SQLite file and subsequent PRAGMAs
            // fail.
            if let dek = dek {
                try applyDEK(handle: h, dek: dek)
            }

            // Reject a future schema before WAL/auto_vacuum PRAGMAs can mutate
            // it. Opening a case with an older binary must be observational.
            let onDiskVersion = try readSchemaVersion(handle: h)
            guard onDiskVersion <= SchemaV1.userVersion else {
                throw ArtifactStoreError.migrationFailed(
                    fromVersion: Int(onDiskVersion),
                    toVersion: Int(SchemaV1.userVersion),
                    message: "database schema is newer than this build"
                )
            }

            // SQLCipher's page size is readable only after the key is applied.
            // Install the hard main-file ceiling after the observational future-
            // schema check, but before WAL/schema writes.
            do {
                try admission.installPageLimit(on: h)
            } catch let error as SQLitePersistentStoreAdmissionError
                where error.isOperationalPressure {
                // Existing oversized case opens for read/inspection in shed mode.
            }

            if !admission.growthBlocked {
                do {
                    try admission.admitWrite(
                        estimatedTransactionBytes: SQLitePersistentStoreAdmission
                            .conservativeRowMutationBytes,
                        on: h
                    )
                    try performOperationalInitialization(
                        handle: h,
                        admission: &admission,
                        existingDatabase: existingDatabase
                    )
                } catch let error as SQLitePersistentStoreAdmissionError
                    where error.isOperationalPressure {
                    // Preserve the keyed handle for read/inspection. The first
                    // later writer retries initialization after fresh probes.
                }
            }
            let pageSizeBytes = try readPageSize(handle: h)
            return (
                h,
                admission,
                pageSizeBytes,
                admission.growthBlocked,
                checkpointController
            )
        } catch {
            checkpointController.detach(from: h)
            sqlite3_close(h)
            throw error
        }
    }

    private static func performOperationalInitialization(
        handle: OpaquePointer,
        admission: inout SQLitePersistentStoreAdmission,
        existingDatabase: Bool
    ) throws {
        for pragma in SchemaV1.openPragmas {
            let rc = sqlite3_exec(handle, pragma, nil, nil, nil)
            guard rc == SQLITE_OK else {
                throw ArtifactStoreError.stepFailed(
                    operation: "open pragma \(pragma)",
                    message: String(cString: sqlite3_errmsg(handle)),
                    code: rc
                )
            }
        }
        try migrate(
            handle: handle,
            admission: &admission,
            existingDatabase: existingDatabase
        )
    }

    private static func defaultStoragePolicy(for databasePath: String)
        -> SQLitePersistentStorePolicy {
        SQLitePersistentStorePolicy(
            maxFootprintBytes: 1_024 * SQLitePersistentStorePolicy.bytesPerMiB,
            freeSpaceFloorBytes: SQLitePersistentStorePolicy.freeSpaceFloorBytes,
            transactionReserveBytes: 16 * 1_048_576,
            storageVolumePath: (databasePath as NSString).deletingLastPathComponent
        )
    }

    deinit {
        if let db {
            checkpointController?.detach(from: db)
            sqlite3_close(db)
        }
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

    private static func readSchemaVersion(handle: OpaquePointer) throws -> Int32 {
        var stmt: OpaquePointer?
        let p = sqlite3_prepare_v2(handle, "PRAGMA user_version", -1, &stmt, nil)
        guard p == SQLITE_OK, let stmt else {
            sqlite3_finalize(stmt)
            throw ArtifactStoreError.migrationFailed(
                fromVersion: 0,
                toVersion: Int(SchemaV1.userVersion),
                message: String(cString: sqlite3_errmsg(handle))
            )
        }
        defer { sqlite3_finalize(stmt) }
        let versionStep = sqlite3_step(stmt)
        guard versionStep == SQLITE_ROW else {
            throw ArtifactStoreError.migrationFailed(
                fromVersion: 0,
                toVersion: Int(SchemaV1.userVersion),
                message: "PRAGMA user_version step failed: \(String(cString: sqlite3_errmsg(handle)))"
            )
        }
        return sqlite3_column_int(stmt, 0)
    }

    private static func migrate(
        handle: OpaquePointer,
        admission: inout SQLitePersistentStoreAdmission,
        existingDatabase: Bool
    ) throws {
        let currentVersion = try readSchemaVersion(handle: handle)

        guard currentVersion <= SchemaV1.userVersion else {
            throw ArtifactStoreError.migrationFailed(
                fromVersion: Int(currentVersion),
                toVersion: Int(SchemaV1.userVersion),
                message: "database schema is newer than this build"
            )
        }

        let baselineStatements = SchemaV1.createDDL
            .components(separatedBy: ";")
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }
        let work = SchemaMigrator.pendingStorageWork(
            on: handle,
            statements: baselineStatements
        )
        let needsVersionBump = currentVersion < SchemaV1.userVersion

        if !work.isEmpty || needsVersionBump {
            // Always resolve the idempotent baseline, even at the latest
            // user_version, so a deleted production index is repaired. Fresh
            // empty files charge every CREATE as bounded metadata; an existing
            // case routes only actually-missing indexes through whole-store
            // rebuild admission.
            if existingDatabase {
                if work.boundedMetadataStatementCount > 0 || needsVersionBump {
                    let metadataCount = work.boundedMetadataStatementCount
                        + (needsVersionBump ? 1 : 0)
                    try admission.admitWrite(
                        estimatedTransactionBytes: SQLitePersistentStoreAdmission
                            .estimatedTransactionBytes(rowCount: metadataCount),
                        on: handle
                    )
                }
                if work.rebuildStatementCount > 0 {
                    try admission.admitSchemaRebuild(
                        operationCount: work.rebuildStatementCount
                    )
                }
            } else {
                let statementCount = work.boundedMetadataStatementCount
                    + work.rebuildStatementCount
                    + (needsVersionBump ? 1 : 0)
                try admission.admitWrite(
                    estimatedTransactionBytes: SQLitePersistentStoreAdmission
                        .estimatedTransactionBytes(rowCount: statementCount),
                    on: handle
                )
            }
            let begin = sqlite3_exec(handle, "BEGIN IMMEDIATE", nil, nil, nil)
            guard begin == SQLITE_OK else {
                throw ArtifactStoreError.migrationFailed(
                    fromVersion: Int(currentVersion),
                    toVersion: Int(SchemaV1.userVersion),
                    message: "BEGIN IMMEDIATE failed: \(String(cString: sqlite3_errmsg(handle)))"
                )
            }
            var committed = false
            defer {
                if !committed { sqlite3_exec(handle, "ROLLBACK", nil, nil, nil) }
            }
            var statements = baselineStatements
            if needsVersionBump {
                statements.append("PRAGMA user_version = \(SchemaV1.userVersion)")
            }
            for sql in statements {
                let rc = sqlite3_exec(handle, sql, nil, nil, nil)
                guard rc == SQLITE_OK else {
                    throw ArtifactStoreError.migrationFailed(
                        fromVersion: Int(currentVersion),
                        toVersion: Int(SchemaV1.userVersion),
                        message: String(cString: sqlite3_errmsg(handle))
                    )
                }
            }
            let commit = sqlite3_exec(handle, "COMMIT", nil, nil, nil)
            guard commit == SQLITE_OK else {
                throw ArtifactStoreError.migrationFailed(
                    fromVersion: Int(currentVersion),
                    toVersion: Int(SchemaV1.userVersion),
                    message: "COMMIT failed: \(String(cString: sqlite3_errmsg(handle)))"
                )
            }
            committed = true
        }
    }

    private static func readPageSize(handle: OpaquePointer) throws -> Int64 {
        var stmt: OpaquePointer?
        let prepare = sqlite3_prepare_v2(handle, "PRAGMA page_size", -1, &stmt, nil)
        guard prepare == SQLITE_OK, let stmt else {
            sqlite3_finalize(stmt)
            throw ArtifactStoreError.stepFailed(
                operation: "read page_size prepare",
                message: String(cString: sqlite3_errmsg(handle)),
                code: prepare
            )
        }
        defer { sqlite3_finalize(stmt) }
        let step = sqlite3_step(stmt)
        guard step == SQLITE_ROW else {
            throw ArtifactStoreError.stepFailed(
                operation: "read page_size step",
                message: String(cString: sqlite3_errmsg(handle)),
                code: step
            )
        }
        let pageSize = sqlite3_column_int64(stmt, 0)
        guard pageSize > 0,
              pageSize <= SQLitePersistentStoreAdmission.maximumSQLitePageBytes else {
            throw ArtifactStoreError.stepFailed(
                operation: "read page_size validate",
                message: "invalid SQLite page size \(pageSize)",
                code: SQLITE_CORRUPT
            )
        }
        return pageSize
    }

    private static func validateSQLiteFamily(path: String) throws {
        var mainExists = false
        var sidecarExists = false
        for suffix in ["", "-wal", "-shm", "-journal"] {
            let member = path + suffix
            var info = stat()
            if lstat(member, &info) == 0 {
                guard (UInt32(info.st_mode) & UInt32(S_IFMT)) == UInt32(S_IFREG),
                      info.st_nlink == 1 else {
                    throw ArtifactStoreError.unsafeSQLitePath(path: member)
                }
                if suffix.isEmpty { mainExists = true } else { sidecarExists = true }
            } else if errno != ENOENT {
                throw ArtifactStoreError.unsafeSQLitePath(path: member)
            }
        }
        if sidecarExists && !mainExists {
            throw ArtifactStoreError.unsafeSQLitePath(path: path)
        }
    }

    private static func executeChecked(
        _ db: OpaquePointer,
        sql: String,
        operation: String
    ) throws {
        let rc = sqlite3_exec(db, sql, nil, nil, nil)
        guard rc == SQLITE_OK else {
            throw ArtifactStoreError.stepFailed(
                operation: operation,
                message: String(cString: sqlite3_errmsg(db)),
                code: rc
            )
        }
    }

    // MARK: - Cases

    /// INSERT a new case record. Idempotent on `cases.id` — calling
    /// twice with the same id is a no-op (silently accepted).
    public func insertCase(_ row: CaseRecord) throws {
        guard let db = db else { return }
        let logicalBytes = Self.logicalRepresentationBytes(
            strings: [
                row.id, row.name, row.notes, row.encryptionState.rawValue,
                // PRIMARY KEY index copy.
                row.id,
            ],
            fixedBytes: 64
        )
        try admitStorageWrite(
            estimatedTransactionBytes: estimatedTransactionBytes(
                logicalRepresentationBytes: logicalBytes,
                maximumLeafPageTouches: 2,
                maximumTreePathPageTouches: 8
            )
        )
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
            try throwLatchedStoragePressureIfPresent(resultCode: step)
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
        let existingBytes = try existingCaseMutationBytes(caseID: caseID)
        try admitStorageWrite(
            estimatedTransactionBytes: SQLitePersistentStoreAdmission
                .saturatingAdd(
                    existingBytes,
                    estimatedTransactionBytes(
                        logicalRepresentationBytes: Self.logicalRepresentationBytes(
                            strings: [caseID], fixedBytes: 16
                        ),
                        maximumLeafPageTouches: 2,
                        maximumTreePathPageTouches: 8
                    )
                )
        )
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
            try throwLatchedStoragePressureIfPresent(resultCode: step)
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
        let existingBytes = try existingCaseMutationBytes(caseID: caseID)
        try admitStorageWrite(
            estimatedTransactionBytes: SQLitePersistentStoreAdmission
                .saturatingAdd(
                    existingBytes,
                    estimatedTransactionBytes(
                        logicalRepresentationBytes: Self.logicalRepresentationBytes(
                            strings: [caseID], fixedBytes: 16
                        ),
                        maximumLeafPageTouches: 2,
                        maximumTreePathPageTouches: 8
                    )
                )
        )
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
            try throwLatchedStoragePressureIfPresent(resultCode: step)
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
        let logicalBytes = Self.logicalRepresentationBytes(
            strings: [
                record.caseID,
                record.pluginID,
                record.pluginVersion,
                record.contentType,
                record.sourcePath,
                record.sha256,
                record.blobRelpath,
                record.summary,
                record.confidence.rawValue,
                record.privacyClass.rawValue,
                record.actor,
                json,
                // Three artifacts secondary-index key copies plus the
                // artifact_data INTEGER PRIMARY KEY representation.
                record.caseID,
                record.caseID,
                record.caseID,
                record.contentType,
                record.privacyClass.rawValue,
            ],
            fixedBytes: 192
        )
        try admitStorageWrite(
            estimatedTransactionBytes: estimatedTransactionBytes(
                logicalRepresentationBytes: logicalBytes,
                maximumLeafPageTouches: 8,
                maximumTreePathPageTouches: 20
            )
        )

        // Wrap the two INSERTs in a savepoint so artifact + payload
        // commit atomically. SAVEPOINT vs BEGIN/COMMIT so it nests
        // correctly under a future write-batching transaction.
        let savepointName = "commit_artifact"
        try executeCheckedForWrite(
            db,
            sql: "SAVEPOINT \(savepointName)",
            operation: "commit begin savepoint"
        )

        var released = false
        defer {
            if !released {
                sqlite3_exec(db, "ROLLBACK TO SAVEPOINT \(savepointName)", nil, nil, nil)
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
            try throwLatchedStoragePressureIfPresent(resultCode: stepA)
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
            try throwLatchedStoragePressureIfPresent(resultCode: stepD)
            throw ArtifactStoreError.stepFailed(
                operation: "commit step data",
                message: String(cString: sqlite3_errmsg(db)),
                code: stepD
            )
        }

        try executeCheckedForWrite(
            db,
            sql: "RELEASE SAVEPOINT \(savepointName)",
            operation: "commit release savepoint"
        )
        released = true

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
        let logicalBytes = Self.logicalRepresentationBytes(
            strings: [
                caseID, pluginID, pluginVersion, inputsJSON, "running",
                // idx_plugin_invocations_case_time key copy.
                caseID,
            ],
            fixedBytes: 48
        )
        try admitStorageWrite(
            estimatedTransactionBytes: estimatedTransactionBytes(
                logicalRepresentationBytes: logicalBytes,
                maximumLeafPageTouches: 3,
                maximumTreePathPageTouches: 8
            )
        )
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
            try throwLatchedStoragePressureIfPresent(resultCode: step)
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
        let existingBytes = try existingInvocationMutationBytes(id: id)
        let logicalBytes = Self.logicalRepresentationBytes(
            strings: [exitStatus, errorMessage, snapshotHash],
            fixedBytes: 64
        )
        try admitStorageWrite(
            estimatedTransactionBytes: SQLitePersistentStoreAdmission
                .saturatingAdd(
                    existingBytes,
                    estimatedTransactionBytes(
                        logicalRepresentationBytes: logicalBytes,
                        maximumLeafPageTouches: 2,
                        maximumTreePathPageTouches: 6
                    )
                )
        )
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
            try throwLatchedStoragePressureIfPresent(resultCode: step)
            throw ArtifactStoreError.stepFailed(
                operation: "recordInvocationEnd step",
                message: String(cString: sqlite3_errmsg(db)),
                code: step
            )
        }
    }

    // MARK: - Read helpers

    private func throwLatchedStoragePressureIfPresent(resultCode: Int32) throws {
        if let pressure = storageAdmission.latchSQLitePressure(
            resultCode: resultCode,
            db: db
        ) {
            throw pressure
        }
    }

    private func existingCaseMutationBytes(caseID: String) throws -> Int64 {
        guard let db else { return 0 }
        let sql = """
            SELECT id, name, created_at, time_window_start, time_window_end,
                   notes, encryption_state, ai_content_allowed, scheduled_trusted
            FROM cases WHERE id = ?1 LIMIT 1
            """
        return try existingRowMutationBytes(
            db: db,
            sql: sql,
            textBinding: caseID,
            columnCount: 9,
            duplicatedIndexColumns: [0],
            indexRepresentationCount: 1,
            maximumLeafPageTouches: 2,
            operation: "existing case estimate"
        )
    }

    private func existingInvocationMutationBytes(id: Int64) throws -> Int64 {
        guard let db else { return 0 }
        let sql = """
            SELECT id, case_id, plugin_id, plugin_version, inputs_json,
                   started_at, completed_at, exit_status, artifacts_committed,
                   artifacts_rejected, error_message, snapshot_hash
            FROM plugin_invocations WHERE id = ?1 LIMIT 1
            """
        return try existingRowMutationBytes(
            db: db,
            sql: sql,
            integerBinding: id,
            columnCount: 12,
            duplicatedIndexColumns: [1],
            indexRepresentationCount: 1,
            maximumLeafPageTouches: 2,
            operation: "existing invocation estimate"
        )
    }

    private func existingRowMutationBytes(
        db: OpaquePointer,
        sql: String,
        textBinding: String? = nil,
        integerBinding: Int64? = nil,
        columnCount: Int32,
        duplicatedIndexColumns: [Int32],
        indexRepresentationCount: Int64,
        maximumLeafPageTouches: Int,
        operation: String
    ) throws -> Int64 {
        var statement: OpaquePointer?
        let prepare = sqlite3_prepare_v2(db, sql, -1, &statement, nil)
        guard prepare == SQLITE_OK, let statement else {
            sqlite3_finalize(statement)
            throw ArtifactStoreError.stepFailed(
                operation: operation,
                message: String(cString: sqlite3_errmsg(db)),
                code: prepare
            )
        }
        defer { sqlite3_finalize(statement) }
        if let textBinding {
            sqlite3_bind_text(statement, 1, textBinding, -1, SQLITE_TRANSIENT)
        } else if let integerBinding {
            sqlite3_bind_int64(statement, 1, integerBinding)
        }
        let step = sqlite3_step(statement)
        if step == SQLITE_DONE { return 0 }
        guard step == SQLITE_ROW else {
            try throwLatchedStoragePressureIfPresent(resultCode: step)
            throw ArtifactStoreError.stepFailed(
                operation: operation,
                message: String(cString: sqlite3_errmsg(db)),
                code: step
            )
        }
        func bytes(_ column: Int32) -> Int64 {
            sqlite3_column_type(statement, column) == SQLITE_NULL
                ? 0 : Int64(sqlite3_column_bytes(statement, column))
        }
        var logical = Int64(columnCount) * 16
        for column in Int32(0)..<columnCount {
            logical = SQLitePersistentStoreAdmission.saturatingAdd(
                logical, bytes(column)
            )
        }
        for column in duplicatedIndexColumns {
            logical = SQLitePersistentStoreAdmission.saturatingAdd(
                logical, bytes(column)
            )
        }
        logical = SQLitePersistentStoreAdmission.saturatingAdd(
            logical,
            SQLitePersistentStoreAdmission.saturatingMultiply(
                indexRepresentationCount, by: 16
            )
        )
        return SQLitePersistentStoreAdmission
            .conservativeEncodedRowMutationBytes(
                logicalRepresentationBytes: logical,
                pageSizeBytes: sqlitePageSizeBytes,
                maximumLeafPageTouches: maximumLeafPageTouches
            )
    }

    private func admitStorageWrite(
        estimatedTransactionBytes: Int64
    ) throws {
        try storageAdmission.admitWrite(
            estimatedTransactionBytes: estimatedTransactionBytes,
            on: db
        )
        guard initializationPending else { return }
        guard let db else {
            throw ArtifactStoreError.stepFailed(
                operation: "storage recovery initialization",
                message: "db handle closed",
                code: SQLITE_MISUSE
            )
        }
        do {
            try Self.performOperationalInitialization(
                handle: db,
                admission: &storageAdmission,
                existingDatabase: true
            )
            initializationPending = false
            // Initialization can itself consume headroom. Re-probe at the
            // application transaction boundary instead of relying on the
            // pre-initialization observation.
            try storageAdmission.admitWrite(
                estimatedTransactionBytes: estimatedTransactionBytes,
                on: db
            )
        } catch {
            let rc = sqlite3_extended_errcode(db)
            if let pressure = storageAdmission.latchSQLitePressure(
                resultCode: rc,
                db: db
            ) {
                throw pressure
            }
            throw error
        }
    }

    private func estimatedTransactionBytes(
        logicalRepresentationBytes: Int64,
        maximumLeafPageTouches: Int,
        maximumTreePathPageTouches: Int
    ) -> Int64 {
        let rowBytes = SQLitePersistentStoreAdmission
            .conservativeEncodedRowMutationBytes(
                logicalRepresentationBytes: logicalRepresentationBytes,
                pageSizeBytes: sqlitePageSizeBytes,
                maximumLeafPageTouches: maximumLeafPageTouches
            )
        return SQLitePersistentStoreAdmission.conservativeTransactionBytes(
            rowMutationBytes: rowBytes,
            pageSizeBytes: sqlitePageSizeBytes,
            maximumTreePathPageTouches: maximumTreePathPageTouches
        )
    }

    private static func logicalRepresentationBytes(
        strings: [String?],
        fixedBytes: Int64
    ) -> Int64 {
        strings.reduce(max(0, fixedBytes)) { total, value in
            guard let value else { return total }
            return SQLitePersistentStoreAdmission.saturatingAdd(
                total,
                Int64(clamping: value.utf8.count)
            )
        }
    }

    private func executeCheckedForWrite(
        _ db: OpaquePointer,
        sql: String,
        operation: String
    ) throws {
        do {
            try Self.executeChecked(db, sql: sql, operation: operation)
        } catch let error as ArtifactStoreError {
            if case .stepFailed(_, _, let code) = error {
                try throwLatchedStoragePressureIfPresent(resultCode: code)
            }
            throw error
        }
    }

    public func storageAdmissionSnapshot() -> SQLitePersistentStoreAdmissionSnapshot {
        storageAdmission.snapshot()
    }

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
