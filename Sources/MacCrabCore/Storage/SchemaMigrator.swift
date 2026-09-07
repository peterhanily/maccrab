// SchemaMigrator.swift
// MacCrabCore
//
// Forward-only SQLite schema migrator keyed on PRAGMA user_version.
// Used by EventStore and AlertStore after base table creation.

import Foundation
import Darwin
import CSQLCipher
import os

/// SQLite preserves the primary result code, extended result code, and the
/// backing VFS errno separately. Capture all three *before* a cleanup ROLLBACK
/// can replace the connection's last-error state. Storage users can then
/// distinguish ENOSPC/EDQUOT from corruption without parsing localized text.
struct SQLiteFailureMetadata: Sendable, Equatable {
    let resultCode: Int32
    let extendedResultCode: Int32
    let systemErrno: Int32

    init(resultCode: Int32, db: OpaquePointer) {
        self.resultCode = resultCode
        self.extendedResultCode = sqlite3_extended_errcode(db)
        self.systemErrno = sqlite3_system_errno(db)
    }

    init(resultCode: Int32, extendedResultCode: Int32, systemErrno: Int32) {
        self.resultCode = resultCode
        self.extendedResultCode = extendedResultCode
        self.systemErrno = systemErrno
    }

    var isStorageExhaustion: Bool {
        let primary = extendedResultCode & 0xFF
        return resultCode == SQLITE_FULL
            || primary == SQLITE_FULL
            || ((resultCode == SQLITE_IOERR || primary == SQLITE_IOERR)
                && (systemErrno == ENOSPC || systemErrno == EDQUOT))
    }
}

/// v1.19.1 (audit): a real os.Logger so the newer-than-binary (downgrade/skew)
/// warning surfaces even though every primary store calls `run()` without the
/// optional `logger:` callback — relying on the callback alone made the warning
/// a silent no-op for EventStore/AlertStore/CampaignStore/TraceStore.
private let migratorLog = Logger(subsystem: "com.maccrab.agent", category: "schema-migrator")

// MARK: - Migration

/// A single ordered schema migration step.
///
/// Each step runs `sql` statements in order inside a transaction, then bumps
/// `PRAGMA user_version` to `version`. Steps are idempotent for `ADD COLUMN`
/// failures: if SQLite reports a duplicate column, the statement is treated
/// as already-applied and skipped.
public struct Migration: Sendable {
    public let version: Int
    public let name: String
    public let sql: [String]

    public init(version: Int, name: String, sql: [String]) {
        self.version = version
        self.name = name
        self.sql = sql
    }
}

/// Storage work that will actually execute after idempotent schema statements
/// are resolved against sqlite_master / table_info. Metadata-only statements
/// fit the ordinary transaction reserve; rebuild statements scale with the
/// existing store and require whole-store headroom from the caller.
public struct SchemaStorageWork: Sendable, Equatable {
    public let boundedMetadataStatementCount: Int
    public let rebuildStatementCount: Int

    public init(
        boundedMetadataStatementCount: Int,
        rebuildStatementCount: Int
    ) {
        self.boundedMetadataStatementCount = boundedMetadataStatementCount
        self.rebuildStatementCount = rebuildStatementCount
    }

    public var isEmpty: Bool {
        boundedMetadataStatementCount == 0 && rebuildStatementCount == 0
    }

    public var boundedTransactionEstimateBytes: Int64 {
        SQLitePersistentStoreAdmission.estimatedTransactionBytes(
            rowCount: boundedMetadataStatementCount
        )
    }
}

// MARK: - Errors

public enum SchemaMigrationError: Error, LocalizedError {
    case migrationFailed(version: Int, name: String, message: String)
    case sqliteFailure(
        version: Int,
        name: String,
        context: String,
        message: String,
        resultCode: Int32,
        extendedResultCode: Int32,
        systemErrno: Int32
    )
    case versionReadFailed(String)
    case versionWriteFailed(String)
    case unknownVersion(current: Int, maxAvailable: Int)
    case quickCheckFailed(String)

    public var errorDescription: String? {
        switch self {
        case let .migrationFailed(v, n, m):
            return "Migration v\(v) '\(n)' failed: \(m)"
        case let .sqliteFailure(v, n, context, message, rc, extended, systemErrno):
            return "Migration v\(v) '\(n)' \(context) failed (rc=\(rc), extended=\(extended), system_errno=\(systemErrno)): \(message)"
        case let .versionReadFailed(m):
            return "Failed to read user_version: \(m)"
        case let .versionWriteFailed(m):
            return "Failed to write user_version: \(m)"
        case let .unknownVersion(current, max):
            return "DB user_version=\(current) exceeds latest known v\(max); binary is older than DB."
        case let .quickCheckFailed(m):
            return "PRAGMA quick_check failed after migrations: \(m)"
        }
    }

    var sqliteFailureMetadata: SQLiteFailureMetadata? {
        guard case let .sqliteFailure(
            _, _, _, _, resultCode, extendedResultCode, systemErrno
        ) = self else { return nil }
        return SQLiteFailureMetadata(
            resultCode: resultCode,
            extendedResultCode: extendedResultCode,
            systemErrno: systemErrno
        )
    }
}

// MARK: - SchemaMigrator

/// Forward-only SQLite schema migrator.
///
/// Usage (inside a store's static `openDatabase` helper):
/// ```
/// let (handle, _, _) = try openRawDB(at: path)
/// try SchemaMigrator.run(on: handle, migrations: Self.migrations)
/// ```
///
/// The migrator reads `PRAGMA user_version`, then reapplies the caller's
/// idempotent migrations in ascending order, each wrapped in `BEGIN/COMMIT`.
/// Only a forward version step advances the shared database counter.
/// On any statement failure the transaction is rolled back and the error is
/// propagated; `user_version` is only bumped after all statements for a step
/// succeed.
public enum SchemaMigrator {

    /// Apply any pending migrations to the given SQLite handle.
    ///
    /// A newer database counter produces a warning here, not a compatibility
    /// verdict. Several stores historically shared that counter, so callers
    /// reapply their own idempotent statements without lowering it.
    ///
    /// Callers must enforce semantic compatibility before invoking this helper.
    /// EventStore v8 has a non-additive journal transition and its own exact
    /// schema/write guards. An older binary is not a supported rollback target
    /// merely because this helper tolerates its database counter. Historical
    /// binaries can quarantine a v8 store and start empty after another open
    /// operation fails; this helper cannot make those binaries safe.
    ///
    /// - Parameters:
    ///   - db: Open SQLite handle (must be writable).
    ///   - migrations: All known migrations. Order-independent; sorted internally.
    ///   - logger: Optional callback for human-readable progress messages.
    /// - Throws: `SchemaMigrationError` on failure. State is left at the last
    ///   successfully committed version. Note: a newer-than-binary `user_version`
    ///   is NOT a failure (see the downgrade policy above).
    public static func run(
        on db: OpaquePointer,
        migrations: [Migration],
        logger: ((String) -> Void)? = nil,
        skipQuickCheck: Bool = false,
        beforeStorageWork: ((SchemaStorageWork) throws -> Void)? = nil
    ) throws {
        let current = try readVersion(db: db)
        let latest = migrations.map(\.version).max() ?? 0

        // v1.7.6: `PRAGMA user_version` is a SINGLE per-database counter,
        // but EventStore + AlertStore (and CampaignStore in the campaigns DB)
        // share their respective files. The previous logic
        //
        //     pending = migrations.filter { $0.version > current }
        //
        // silently dropped a store's pending migrations whenever a co-resident
        // store had already bumped the counter. Reproduced in the field on
        // a v1.7.5 install: EventStore opened first, ran its v1..v2, counter=2;
        // AlertStore opened second, current==latest==2, pending=[], v2
        // ADD COLUMN llm_investigation_json was never applied → AlertStore's
        // INSERT prepare crashed at every boot, daemon crash-loop, "Detection
        // engine appears silent" banner.
        //
        // Fix: always run all of THIS store's migrations, in version order.
        // - apply() is idempotent for ADD COLUMN (duplicate-column-name handler).
        // - Callers use CREATE [TABLE|INDEX] IF NOT EXISTS for table/index ops.
        // - Bump user_version only on a forward step (m.version > current).
        //   Lowering the counter would mis-fire the leader store's filter
        //   on the next boot.
        //
        // Cost: a handful of cheap fail-fast SQLite calls per store init.
        // Non-idempotent work needs caller-specific transition state and
        // admission. EventStore handles its journal transition separately.
        let sorted = migrations.sorted(by: { $0.version < $1.version })
        if current > latest {
            // Surface version skew even when no logger callback was supplied.
            // Store-specific compatibility checks remain the caller's job;
            // a tolerated counter alone does not prove safe reads or writes.
            let msg = "DB user_version=\(current) EXCEEDS this binary's latest known v\(latest) — running an OLDER MacCrab against a newer-schema database (downgrade/rollback / mixed-version fleet?). Proceeding additively; upgrade to the build that wrote this DB if you see schema errors."
            // Log via BOTH the optional callback AND os.Logger.warning — the
            // primary stores pass no callback, so the os.Logger is what actually
            // surfaces this version-skew to `log show` / fleet telemetry.
            logger?("WARNING: \(msg)")
            migratorLog.warning("\(msg, privacy: .public)")
        } else if current == latest {
            // at-or-ahead case: the per-database counter is already at THIS
            // store's latest (a co-resident store bumped it first), so re-apply
            // every migration idempotently with bumpVersion=false instead of
            // skipping them — the v1.7.6 fix for the silently-dropped-migration
            // crash. (apply() handles bumpVersion; markers asserted by Pass 10.)
            logger?("DB user_version=\(current) at v\(latest); re-applying \(sorted.count) migration(s) idempotently (no counter change)")
        } else {
            logger?("Migrating schema from v\(current) to v\(latest)")
        }
        for m in sorted {
            // Only bump on forward progress; otherwise leave the counter alone.
            let bump = m.version > current
            try apply(
                m,
                db: db,
                bumpVersion: bump,
                logger: logger,
                beforeStorageWork: beforeStorageWork
            )
        }

        // Post-migration quick_check: catches structure-level corruption
        // (orphan rowids, broken indexes, malformed pages) that didn't
        // surface during the migration's writes themselves. Originally
        // billed as "sub-second on a 500 MB DB" (v1.10 audit hardening),
        // but field measurement on a 962 MB events.db with FTS5 puts it
        // at 1–2 s of synchronous PRAGMA work — significant chunk of
        // daemon cold-start time. EventStore skips this full SQLite pass;
        // it does not schedule a deferred task. Its startup journal/schema
        // validation has a different scope. Operators can explicitly request
        // the bounded read-only `maccrabctl storage check` diagnostic. A
        // successful ordinary query is not a full-store integrity verdict.
        if !skipQuickCheck {
            try quickCheck(db: db, logger: logger)
        }
    }

    /// Run `PRAGMA quick_check`. Throws `quickCheckFailed` if SQLite reports
    /// anything other than the literal `ok` row — that's the documented
    /// SQLite contract. Logs the issues at warn level for diagnostic capture
    /// before throwing.
    public static func quickCheck(
        on db: OpaquePointer,
        logger: ((String) -> Void)? = nil
    ) throws {
        try quickCheck(db: db, logger: logger)
    }

    private static func quickCheck(
        db: OpaquePointer,
        logger: ((String) -> Void)?
    ) throws {
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, "PRAGMA quick_check", -1, &stmt, nil) == SQLITE_OK else {
            let msg = String(cString: sqlite3_errmsg(db))
            throw SchemaMigrationError.quickCheckFailed("prepare failed: \(msg)")
        }
        defer { sqlite3_finalize(stmt) }

        var issues: [String] = []
        var rows = 0
        var result = sqlite3_step(stmt)
        while result == SQLITE_ROW {
            rows += 1
            if let cstr = sqlite3_column_text(stmt, 0) {
                let row = String(cString: cstr)
                if row != "ok" { issues.append(row) }
            } else {
                issues.append("quick_check returned a null result")
            }
            result = sqlite3_step(stmt)
        }
        guard result == SQLITE_DONE, rows > 0 else {
            throw SchemaMigrationError.quickCheckFailed("check did not complete (SQLite rc=\(result))")
        }
        if !issues.isEmpty {
            let summary = issues.prefix(5).joined(separator: "; ")
            logger?("  quick_check FAILED: \(summary)")
            throw SchemaMigrationError.quickCheckFailed(summary)
        }
        logger?("  quick_check ok")
    }

    /// Read the current `PRAGMA user_version`. Returns 0 for a fresh DB.
    public static func readVersion(db: OpaquePointer) throws -> Int {
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, "PRAGMA user_version", -1, &stmt, nil) == SQLITE_OK else {
            let msg = String(cString: sqlite3_errmsg(db))
            throw SchemaMigrationError.versionReadFailed(msg)
        }
        defer { sqlite3_finalize(stmt) }

        guard sqlite3_step(stmt) == SQLITE_ROW else {
            throw SchemaMigrationError.versionReadFailed("no row from PRAGMA user_version")
        }
        return Int(sqlite3_column_int(stmt, 0))
    }

    /// Resolve an idempotent schema statement list before it is executed.
    /// Existing CREATE ... IF NOT EXISTS objects and already-added columns are
    /// excluded, preventing every daemon restart from demanding rebuild-sized
    /// scratch for operations that SQLite will treat as no-ops.
    public static func pendingStorageWork(
        on db: OpaquePointer,
        statements: [String]
    ) -> SchemaStorageWork {
        var metadata = 0
        var rebuilds = 0
        for sql in statements {
            switch classifyPendingStatement(sql, db: db) {
            case .none:
                break
            case .boundedMetadata:
                metadata += 1
            case .storeRebuild:
                rebuilds += 1
            }
        }
        return SchemaStorageWork(
            boundedMetadataStatementCount: metadata,
            rebuildStatementCount: rebuilds
        )
    }

    // MARK: - Private

    private static func apply(
        _ m: Migration,
        db: OpaquePointer,
        bumpVersion: Bool = true,
        logger: ((String) -> Void)?,
        beforeStorageWork: ((SchemaStorageWork) throws -> Void)?
    ) throws {
        logger?("  Applying v\(m.version): \(m.name)\(bumpVersion ? "" : " (idempotent re-run, no version bump)")")

        let pending = pendingStorageWork(on: db, statements: m.sql)
        // `PRAGMA user_version = N` is itself a persistent header mutation.
        // Include it even for an otherwise-empty baseline migration so no
        // schema transaction can begin without an explicit bounded admission.
        let storageWork = SchemaStorageWork(
            boundedMetadataStatementCount:
                pending.boundedMetadataStatementCount + (bumpVersion ? 1 : 0),
            rebuildStatementCount: pending.rebuildStatementCount
        )
        if !storageWork.isEmpty {
            // This callback runs before BEGIN so a headroom refusal never
            // leaves an open transaction or partially-applied migration.
            try beforeStorageWork?(storageWork)
        }

        guard sqlite3_exec(db, "BEGIN TRANSACTION", nil, nil, nil) == SQLITE_OK else {
            let msg = String(cString: sqlite3_errmsg(db))
            let failure = SQLiteFailureMetadata(
                resultCode: sqlite3_errcode(db), db: db)
            throw SchemaMigrationError.sqliteFailure(
                version: m.version, name: m.name, context: "BEGIN",
                message: msg, resultCode: failure.resultCode,
                extendedResultCode: failure.extendedResultCode,
                systemErrno: failure.systemErrno
            )
        }

        for sql in m.sql {
            var errmsg: UnsafeMutablePointer<CChar>?
            let rc = sqlite3_exec(db, sql, nil, nil, &errmsg)
            if rc != SQLITE_OK {
                let msg = errmsg.flatMap { String(cString: $0) } ?? "unknown error"
                let failure = SQLiteFailureMetadata(resultCode: rc, db: db)
                sqlite3_free(errmsg)

                // Treat "already-exists" failures as idempotent re-runs — lets the
                // co-resident-store branch in run() safely re-apply CREATE / ALTER
                // statements that previously succeeded. v1.7.6 broadened this from
                // ADD-COLUMN-only to also cover bare CREATE TABLE / CREATE INDEX
                // (callers should use IF NOT EXISTS, but this is defense in depth
                // for migrations that pre-date the convention).
                let lower = msg.lowercased()
                if lower.contains("duplicate column name")
                    || lower.contains("already exists") {
                    logger?("    skip (already applied): \(sql.prefix(80))")
                    continue
                }

                sqlite3_exec(db, "ROLLBACK", nil, nil, nil)
                throw SchemaMigrationError.sqliteFailure(
                    version: m.version, name: m.name,
                    context: String(sql.prefix(120)), message: msg,
                    resultCode: failure.resultCode,
                    extendedResultCode: failure.extendedResultCode,
                    systemErrno: failure.systemErrno
                )
            }
        }

        // PRAGMA user_version supports parameterized values poorly; use literal.
        // Skip the bump on idempotent re-runs (v1.7.6) — the counter is already
        // ahead of m.version, set by another co-resident store. Lowering it
        // would make EventStore's pending-migration filter mis-fire next boot.
        if bumpVersion {
            let bumpSQL = "PRAGMA user_version = \(m.version)"
            let rc = sqlite3_exec(db, bumpSQL, nil, nil, nil)
            if rc != SQLITE_OK {
                let msg = String(cString: sqlite3_errmsg(db))
                let failure = SQLiteFailureMetadata(resultCode: rc, db: db)
                sqlite3_exec(db, "ROLLBACK", nil, nil, nil)
                throw SchemaMigrationError.sqliteFailure(
                    version: m.version, name: m.name, context: "user_version",
                    message: msg, resultCode: failure.resultCode,
                    extendedResultCode: failure.extendedResultCode,
                    systemErrno: failure.systemErrno
                )
            }
        }

        let commitRC = sqlite3_exec(db, "COMMIT", nil, nil, nil)
        if commitRC != SQLITE_OK {
            let msg = String(cString: sqlite3_errmsg(db))
            let failure = SQLiteFailureMetadata(resultCode: commitRC, db: db)
            sqlite3_exec(db, "ROLLBACK", nil, nil, nil)
            throw SchemaMigrationError.sqliteFailure(
                version: m.version, name: m.name, context: "COMMIT",
                message: msg, resultCode: failure.resultCode,
                extendedResultCode: failure.extendedResultCode,
                systemErrno: failure.systemErrno
            )
        }
    }

    private enum PendingStatementClass {
        case none
        case boundedMetadata
        case storeRebuild
    }

    private static func classifyPendingStatement(
        _ sql: String,
        db: OpaquePointer
    ) -> PendingStatementClass {
        let tokens = schemaTokens(sql)
        let upper = tokens.map { $0.uppercased() }
        guard let first = upper.first else { return .none }

        if first == "CREATE" {
            if let indexPosition = upper.firstIndex(of: "INDEX"),
               let name = objectName(after: indexPosition, tokens: tokens, upper: upper) {
                return schemaObjectExists(db: db, type: "index", name: name)
                    ? .none : .storeRebuild
            }
            if let tablePosition = upper.firstIndex(of: "TABLE"),
               let name = objectName(after: tablePosition, tokens: tokens, upper: upper) {
                if schemaObjectExists(db: db, type: "table", name: name) {
                    return .none
                }
                // CREATE TABLE AS SELECT and unknown virtual-table modules can
                // copy existing content. Ordinary empty/bootstrap tables are
                // metadata bounded.
                let normalized = " " + upper.joined(separator: " ") + " "
                return upper.contains("VIRTUAL")
                    || normalized.contains(" AS SELECT ")
                    ? .storeRebuild : .boundedMetadata
            }
            if let triggerPosition = upper.firstIndex(of: "TRIGGER"),
               let name = objectName(after: triggerPosition, tokens: tokens, upper: upper) {
                return schemaObjectExists(db: db, type: "trigger", name: name)
                    ? .none : .boundedMetadata
            }
            if let viewPosition = upper.firstIndex(of: "VIEW"),
               let name = objectName(after: viewPosition, tokens: tokens, upper: upper) {
                return schemaObjectExists(db: db, type: "view", name: name)
                    ? .none : .boundedMetadata
            }
            return .storeRebuild
        }

        if first == "DROP" {
            if let indexPosition = upper.firstIndex(of: "INDEX"),
               let name = objectName(after: indexPosition, tokens: tokens, upper: upper) {
                return schemaObjectExists(db: db, type: "index", name: name)
                    ? .storeRebuild : .none
            }
            if let tablePosition = upper.firstIndex(of: "TABLE"),
               let name = objectName(after: tablePosition, tokens: tokens, upper: upper) {
                return schemaObjectExists(db: db, type: "table", name: name)
                    ? .storeRebuild : .none
            }
            if let triggerPosition = upper.firstIndex(of: "TRIGGER"),
               let name = objectName(after: triggerPosition, tokens: tokens, upper: upper) {
                return schemaObjectExists(db: db, type: "trigger", name: name)
                    ? .boundedMetadata : .none
            }
            return .storeRebuild
        }

        if first == "ALTER", upper.count >= 6, upper[1] == "TABLE" {
            let table = tokens[2]
            guard let add = upper.firstIndex(of: "ADD") else {
                return .storeRebuild
            }
            var columnPosition = add + 1
            if columnPosition < upper.count, upper[columnPosition] == "COLUMN" {
                columnPosition += 1
            }
            guard columnPosition < tokens.count else { return .storeRebuild }
            return tableHasColumn(db: db, table: table, column: tokens[columnPosition])
                ? .none : .boundedMetadata
        }

        // Migration bodies are expected to be DDL. Treat any future/unknown
        // statement as rebuild-class so adding data-copy SQL cannot silently
        // bypass whole-store admission.
        return .storeRebuild
    }

    private static func schemaTokens(_ sql: String) -> [String] {
        // DDL bundles (notably the SQLCipher ArtifactStore baseline) retain
        // human-readable `--` comments in each split statement. Ignore comment
        // tails before tokenizing so classification sees CREATE/DROP rather
        // than conservatively treating the leading comment marker as unknown
        // rebuild work.
        let uncommented = sql.split(
            separator: "\n",
            omittingEmptySubsequences: false
        ).map { line -> String in
            let text = String(line)
            guard let marker = text.range(of: "--") else { return text }
            return String(text[..<marker.lowerBound])
        }.joined(separator: "\n")
        let separators = CharacterSet.whitespacesAndNewlines.union(
            CharacterSet(charactersIn: "(),;`\"[]")
        )
        return uncommented.components(separatedBy: separators)
            .filter { !$0.isEmpty }
    }

    private static func objectName(
        after keywordPosition: Int,
        tokens: [String],
        upper: [String]
    ) -> String? {
        var position = keywordPosition + 1
        if position + 2 < upper.count,
           upper[position] == "IF",
           upper[position + 1] == "NOT",
           upper[position + 2] == "EXISTS" {
            position += 3
        } else if position + 1 < upper.count,
                  upper[position] == "IF",
                  upper[position + 1] == "EXISTS" {
            position += 2
        }
        guard position < tokens.count else { return nil }
        return tokens[position]
    }

    private static func schemaObjectExists(
        db: OpaquePointer,
        type: String,
        name: String
    ) -> Bool {
        var stmt: OpaquePointer?
        let sql = "SELECT 1 FROM sqlite_master WHERE type = ?1 AND name = ?2 COLLATE NOCASE LIMIT 1"
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK,
              let stmt else {
            return false
        }
        defer { sqlite3_finalize(stmt) }
        let transient = unsafeBitCast(
            OpaquePointer(bitPattern: -1)!,
            to: sqlite3_destructor_type.self
        )
        sqlite3_bind_text(stmt, 1, type, -1, transient)
        sqlite3_bind_text(stmt, 2, name, -1, transient)
        return sqlite3_step(stmt) == SQLITE_ROW
    }

    private static func tableHasColumn(
        db: OpaquePointer,
        table: String,
        column: String
    ) -> Bool {
        let escaped = table.replacingOccurrences(of: "\"", with: "\"\"")
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(
            db,
            "PRAGMA table_info(\"\(escaped)\")",
            -1,
            &stmt,
            nil
        ) == SQLITE_OK, let stmt else {
            return false
        }
        defer { sqlite3_finalize(stmt) }
        while sqlite3_step(stmt) == SQLITE_ROW {
            guard let name = sqlite3_column_text(stmt, 1) else { continue }
            if String(cString: name).caseInsensitiveCompare(column) == .orderedSame {
                return true
            }
        }
        return false
    }
}
