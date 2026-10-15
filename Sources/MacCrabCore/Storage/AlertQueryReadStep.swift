import CSQLCipher

/// A read is complete only at SQLITE_DONE. In particular, a yielded prefix
/// followed by BUSY/INTERRUPT/IOERR must never become a successful short list.
enum AlertQueryReadStep {
    static func advance(
        statement: OpaquePointer,
        database: OpaquePointer?,
        step: (OpaquePointer?) -> Int32 = { sqlite3_step($0) }
    ) throws -> Bool {
        try Task.checkCancellation()
        let result = step(statement)
        switch result {
        case SQLITE_ROW, SQLITE_DONE:
            try Task.checkCancellation()
            return result == SQLITE_ROW
        default:
            // Capture connection diagnostics while the statement is still
            // alive; finalization can replace SQLite's last error state.
            let failure = SQLiteFailureDetails(resultCode: result, db: database)
            let message = database.map { String(cString: sqlite3_errmsg($0)) }
                ?? "alert query did not complete"
            throw AlertStoreError.sqliteFailure(
                context: "alert query step", message: message,
                resultCode: failure.resultCode,
                extendedResultCode: failure.extendedResultCode,
                systemErrno: failure.systemErrno
            )
        }
    }
}
