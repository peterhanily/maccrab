import Foundation
import CSQLCipher

/// An explicit maintenance read. It neither initializes a store nor migrates,
/// quarantines, repairs, or checkpoints it. Use against the selected engine's
/// existing plaintext SQLite stores; encrypted forensic cases need their key.
public enum SQLiteIntegrityDiagnostic {
    public struct Result: Codable, Sendable, Equatable {
        public let database: String
        public let status: String
        public let elapsedSeconds: Double
        public let sqliteCode: Int32?
        public let issueCount: Int
    }

    private final class Deadline {
        let instant: ContinuousClock.Instant
        init(seconds: Double) { instant = .now.advanced(by: .seconds(seconds)) }
    }

    /// The deadline bounds SQLite virtual-machine work, including quick_check;
    /// it is not a guarantee against an uninterruptible filesystem operation.
    public static func check(database: URL, timeoutSeconds: Double = 30) -> Result {
        let started = ContinuousClock.now
        func finish(_ status: String, code: Int32? = nil, issues: Int = 0) -> Result {
            let elapsed = started.duration(to: .now).components
            return Result(database: database.lastPathComponent, status: status,
                          elapsedSeconds: Double(elapsed.seconds)
                              + Double(elapsed.attoseconds) / 1e18,
                          sqliteCode: code, issueCount: issues)
        }
        guard timeoutSeconds.isFinite, timeoutSeconds > 0, timeoutSeconds <= 300 else {
            return finish("invalid_budget")
        }
        guard let attributes = try? FileManager.default.attributesOfItem(atPath: database.path) else {
            return finish("unavailable")
        }
        guard attributes[.type] as? FileAttributeType == .typeRegular else {
            return finish("unsupported_file")
        }
        let deadline = Deadline(seconds: timeoutSeconds)
        var raw: OpaquePointer?
        let opened = SQLiteOpenPathPolicy.open(
            database.path,
            database: &raw,
            flags: SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX
        )
        defer { if let raw { sqlite3_close(raw) } }
        guard opened == SQLITE_OK, let raw else { return finish("unavailable", code: opened) }
        sqlite3_busy_timeout(raw, 250)
        let context = Unmanaged.passUnretained(deadline).toOpaque()
        sqlite3_progress_handler(raw, 1000, { context in
            guard let context else { return 1 }
            let deadline = Unmanaged<Deadline>.fromOpaque(context).takeUnretainedValue()
            return ContinuousClock.now >= deadline.instant ? 1 : 0
        }, context)
        defer {
            sqlite3_progress_handler(raw, 0, nil, nil)
            withExtendedLifetime(deadline) {}
        }
        var statement: OpaquePointer?
        let prepared = sqlite3_prepare_v2(raw, "PRAGMA quick_check", -1, &statement, nil)
        defer { sqlite3_finalize(statement) }
        guard prepared == SQLITE_OK else {
            return finish(prepared == SQLITE_INTERRUPT ? "incomplete" : "failed", code: prepared)
        }
        var rows = 0
        var issues = 0
        while true {
            guard ContinuousClock.now < deadline.instant else { return finish("incomplete") }
            let code = sqlite3_step(statement)
            if code == SQLITE_DONE {
                return finish(rows == 1 && issues == 0 ? "passed" : "failed", issues: issues)
            }
            guard code == SQLITE_ROW else {
                return finish(code == SQLITE_INTERRUPT || code == SQLITE_BUSY || code == SQLITE_LOCKED
                    ? "incomplete" : "failed", code: code, issues: issues)
            }
            rows += 1
            if sqlite3_column_text(statement, 0).map({ String(cString: $0) }) != "ok" {
                issues += 1
            }
        }
    }
}
