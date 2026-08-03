import Testing
import Darwin
import CSQLCipher
@testable import MacCrabCore

@Suite("SQLite corruption recovery classification")
struct SQLiteFailureClassifierTests {
    @Test("only explicit CORRUPT and NOTADB families authorize quarantine")
    func explicitCorruptionOnly() {
        let quarantine: [(Int32, Int32)] = [
            (SQLITE_CORRUPT, SQLITE_CORRUPT),
            (SQLITE_NOTADB, SQLITE_NOTADB),
            (SQLITE_ERROR, SQLITE_CORRUPT | Int32(1 << 8)),
        ]
        for (result, extended) in quarantine {
            #expect(SQLiteFailureClassifier.disposition(
                resultCode: result,
                extendedResultCode: extended
            ) == .quarantineExplicitCorruption)
        }

        let preserve: [(Int32, Int32, Int32)] = [
            (SQLITE_BUSY, SQLITE_BUSY, 0),
            (SQLITE_LOCKED, SQLITE_LOCKED, 0),
            (SQLITE_PERM, SQLITE_PERM, EPERM),
            (SQLITE_READONLY, SQLITE_READONLY, EROFS),
            (SQLITE_IOERR, SQLITE_IOERR, EIO),
            (SQLITE_IOERR, SQLITE_IOERR | Int32(3 << 8), ENOSPC),
            (SQLITE_FULL, SQLITE_FULL, ENOSPC),
        ]
        for (result, extended, systemErrno) in preserve {
            let details = SQLiteFailureDetails(
                resultCode: result,
                extendedResultCode: extended,
                systemErrno: systemErrno
            )
            #expect(!details.isExplicitCorruption)
            #expect(SQLiteFailureClassifier.disposition(
                resultCode: result,
                extendedResultCode: extended
            ) == .preserveEvidenceAndFail)
        }
    }

    @Test("typed store errors preserve primary, extended, and VFS errno")
    func typedMetadataRoundTrip() {
        let error = EventStoreError.sqliteFailure(
            context: "open",
            message: "input/output error",
            resultCode: SQLITE_IOERR,
            extendedResultCode: SQLITE_IOERR | Int32(3 << 8),
            systemErrno: EIO
        )
        let details = SQLiteFailureClassifier.details(from: error)
        #expect(details == SQLiteFailureDetails(
            resultCode: SQLITE_IOERR,
            extendedResultCode: SQLITE_IOERR | Int32(3 << 8),
            systemErrno: EIO
        ))
        #expect(SQLiteFailureClassifier.disposition(for: error) == .preserveEvidenceAndFail)
    }

    @Test("retryable and disk-pressure errors retain structured SQLite metadata")
    func specializedErrorsRetainMetadata() {
        let busyDetails = SQLiteFailureDetails(
            resultCode: SQLITE_BUSY,
            extendedResultCode: SQLITE_BUSY,
            systemErrno: EBUSY
        )
        let busy = EventStoreError.busy("database is locked", failure: busyDetails)
        #expect(SQLiteFailureClassifier.details(from: busy) == busyDetails)
        #expect(SQLiteFailureClassifier.disposition(for: busy) == .preserveEvidenceAndFail)

        let fullDetails = SQLiteFailureDetails(
            resultCode: SQLITE_IOERR,
            extendedResultCode: SQLITE_IOERR | Int32(12 << 8),
            systemErrno: ENOSPC
        )
        let eventFull = EventStoreError.diskFull("no space", failure: fullDetails)
        let alertFull = AlertStoreError.diskFull("no space", failure: fullDetails)
        #expect(SQLiteFailureClassifier.details(from: eventFull) == fullDetails)
        #expect(SQLiteFailureClassifier.details(from: alertFull) == fullDetails)
        #expect(SQLiteFailureClassifier.disposition(for: eventFull) == .preserveEvidenceAndFail)
        #expect(SQLiteFailureClassifier.disposition(for: alertFull) == .preserveEvidenceAndFail)

        // Compatibility constructors still work for injected/transient test
        // errors, but correctly report that no low-level SQLite state exists.
        #expect(SQLiteFailureClassifier.details(
            from: EventStoreError.busy("synthetic")
        ) == nil)
    }
}
