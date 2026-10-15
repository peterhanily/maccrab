import CSQLCipher

/// Inspection only: no SQL, checkpoint, rollback or connection mutation. The
/// owner must close admission and account for queued calls BEFORE asking for
/// this point-in-time certificate, then maintain exclusive idle ownership.
enum SQLiteIdleReadCertificate {
    static func permitsRetention(_ db: OpaquePointer?, readOnly: Bool) -> Bool {
        guard readOnly, let db, sqlite3_db_readonly(db, "main") == 1,
              sqlite3_get_autocommit(db) != 0 else { return false }
        var moved: Int32 = 0
        guard sqlite3_file_control(db, "main", SQLITE_FCNTL_HAS_MOVED, &moved) == SQLITE_OK,
              moved == 0 else { return false }
        var statement = sqlite3_next_stmt(db, nil)
        var inspected = 0
        while let current = statement {
            // A certificate is optional; unexpectedly many retained statements
            // fall back to permanent retirement rather than unbounded work.
            guard inspected < 1_024, sqlite3_stmt_busy(current) == 0 else { return false }
            inspected += 1
            statement = sqlite3_next_stmt(db, current)
        }
        return sqlite3_get_autocommit(db) != 0
    }
}
