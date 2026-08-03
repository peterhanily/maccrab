// SQLiteFailureClassifier.swift
// MacCrabCore
//
// Central recovery policy for SQLite failures.  Recovery callers must never
// infer corruption from an error string: only SQLITE_CORRUPT / SQLITE_NOTADB
// (including their extended result codes) authorize moving evidence aside.

import CSQLCipher

/// The SQLite/VFS failure state captured before rollback, finalization, or
/// close can replace the connection's last-error state.
public struct SQLiteFailureDetails: Sendable, Equatable {
    public let resultCode: Int32
    public let extendedResultCode: Int32
    public let systemErrno: Int32

    public init(
        resultCode: Int32,
        extendedResultCode: Int32,
        systemErrno: Int32
    ) {
        self.resultCode = resultCode
        self.extendedResultCode = extendedResultCode
        self.systemErrno = systemErrno
    }

    init(resultCode: Int32, db: OpaquePointer?) {
        self.resultCode = resultCode
        self.extendedResultCode = db.map(sqlite3_extended_errcode) ?? resultCode
        self.systemErrno = db.map(sqlite3_system_errno) ?? 0
    }

    /// SQLite extended codes retain the primary code in the low byte.
    public var primaryResultCode: Int32 {
        extendedResultCode & 0xFF
    }

    public var isExplicitCorruption: Bool {
        SQLiteFailureClassifier.isExplicitCorruption(
            resultCode: resultCode,
            extendedResultCode: extendedResultCode
        )
    }
}

/// Every non-corruption result is deliberately grouped into preserve-and-fail:
/// lock contention, permissions, read-only media, I/O errors, and exhaustion
/// must remain visible to the caller and must not cause evidence to be moved.
public enum SQLiteRecoveryDisposition: String, Sendable, Equatable {
    case quarantineExplicitCorruption
    case preserveEvidenceAndFail
}

/// Errors that retain SQLite's primary/extended result codes and VFS errno can
/// opt into generic recovery classification without string parsing.
public protocol SQLiteFailureReporting: Error {
    var sqliteFailureDetails: SQLiteFailureDetails? { get }
}

public enum SQLiteFailureClassifier {
    public static func disposition(
        resultCode: Int32,
        extendedResultCode: Int32
    ) -> SQLiteRecoveryDisposition {
        isExplicitCorruption(
            resultCode: resultCode,
            extendedResultCode: extendedResultCode
        ) ? .quarantineExplicitCorruption : .preserveEvidenceAndFail
    }

    /// Only explicit SQLite corruption families authorize quarantine.  Do not
    /// add SQLITE_IOERR here: an I/O error can be transient, permission-related,
    /// or storage pressure, and moving the store would destroy the best evidence
    /// of the underlying failure.
    public static func isExplicitCorruption(
        resultCode: Int32,
        extendedResultCode: Int32
    ) -> Bool {
        let resultPrimary = resultCode & 0xFF
        let extendedPrimary = extendedResultCode & 0xFF
        return resultPrimary == SQLITE_CORRUPT
            || resultPrimary == SQLITE_NOTADB
            || extendedPrimary == SQLITE_CORRUPT
            || extendedPrimary == SQLITE_NOTADB
    }

    public static func details(from error: Error) -> SQLiteFailureDetails? {
        (error as? any SQLiteFailureReporting)?.sqliteFailureDetails
    }

    public static func disposition(for error: Error) -> SQLiteRecoveryDisposition? {
        guard let details = details(from: error) else { return nil }
        return disposition(
            resultCode: details.resultCode,
            extendedResultCode: details.extendedResultCode
        )
    }
}

extension SQLiteFailureMetadata {
    var publicDetails: SQLiteFailureDetails {
        SQLiteFailureDetails(
            resultCode: resultCode,
            extendedResultCode: extendedResultCode,
            systemErrno: systemErrno
        )
    }
}

extension SchemaMigrationError: SQLiteFailureReporting {
    public var sqliteFailureDetails: SQLiteFailureDetails? {
        guard case let .sqliteFailure(
            _, _, _, _, resultCode, extendedResultCode, systemErrno
        ) = self else { return nil }
        return SQLiteFailureDetails(
            resultCode: resultCode,
            extendedResultCode: extendedResultCode,
            systemErrno: systemErrno
        )
    }
}

extension CausalGraphStoreError: SQLiteFailureReporting {
    public var sqliteFailureDetails: SQLiteFailureDetails? {
        guard case let .sqliteFailure(
            _, _, resultCode, extendedResultCode, systemErrno
        ) = self else { return nil }
        return SQLiteFailureDetails(
            resultCode: resultCode,
            extendedResultCode: extendedResultCode,
            systemErrno: systemErrno
        )
    }
}

extension EventStoreError: SQLiteFailureReporting {
    public var sqliteFailureDetails: SQLiteFailureDetails? {
        switch self {
        case .diskFull(_, let failure), .busy(_, let failure):
            return failure
        case let .sqliteFailure(
            _, _, resultCode, extendedResultCode, systemErrno
        ):
            return SQLiteFailureDetails(
                resultCode: resultCode,
                extendedResultCode: extendedResultCode,
                systemErrno: systemErrno
            )
        default:
            return nil
        }
    }
}

extension AlertStoreError: SQLiteFailureReporting {
    public var sqliteFailureDetails: SQLiteFailureDetails? {
        switch self {
        case .diskFull(_, let failure):
            return failure
        case let .sqliteFailure(
            _, _, resultCode, extendedResultCode, systemErrno
        ):
            return SQLiteFailureDetails(
                resultCode: resultCode,
                extendedResultCode: extendedResultCode,
                systemErrno: systemErrno
            )
        default:
            return nil
        }
    }
}
