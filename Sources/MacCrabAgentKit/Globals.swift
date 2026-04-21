import Foundation
import os.log
import MacCrabCore

/// Shared logger for the daemon process.
let logger = Logger(subsystem: "com.maccrab.agent", category: "main")

/// Track and throttle storage error logging to avoid log spam on persistent failures.
///
/// v1.4.3 (fail-loud): a snapshot of the counters + most-recent error
/// message is persisted to a well-known JSON file after every
/// record. The dashboard polls this file and raises a red banner so
/// users notice that inserts are silently failing (disk full, DB
/// locked, permissions denied). Before v1.4.3 storage errors lived
/// only in os_log — correct but invisible to anyone who wasn't
/// running `sudo log show`.
actor StorageErrorTracker {
    static let shared = StorageErrorTracker()
    private var alertInsertErrors: Int = 0
    private var eventInsertErrors: Int = 0
    private var lastAlertErrorLog: Date = .distantPast
    private var lastEventErrorLog: Date = .distantPast
    private var lastErrorMessage: String = ""
    private var lastErrorKind: String = ""
    private var lastErrorAt: Date?

    /// Well-known path the dashboard polls. Sits alongside the DB in
    /// `/Library/Application Support/MacCrab/` so file permissions
    /// match the rest of the managed-state tree: sysext (root)
    /// writes, non-root dashboard reads.
    private let snapshotPath = "/Library/Application Support/MacCrab/storage_errors.json"

    func recordAlertError(_ error: Error) {
        alertInsertErrors += 1
        lastErrorMessage = error.localizedDescription
        lastErrorKind = "alert_insert"
        lastErrorAt = Date()
        if Date().timeIntervalSince(lastAlertErrorLog) > 60 {
            let count = self.alertInsertErrors
            logger.error("Alert insert failed (\(count, privacy: .public) total): \(error.localizedDescription, privacy: .public)")
            lastAlertErrorLog = Date()
        }
        writeSnapshot()
    }

    func recordEventError(_ error: Error) {
        eventInsertErrors += 1
        lastErrorMessage = error.localizedDescription
        lastErrorKind = "event_insert"
        lastErrorAt = Date()
        if Date().timeIntervalSince(lastEventErrorLog) > 60 {
            let count = self.eventInsertErrors
            logger.error("Event insert failed (\(count, privacy: .public) total): \(error.localizedDescription, privacy: .public)")
            lastEventErrorLog = Date()
        }
        writeSnapshot()
    }

    /// Serialize current counters + most-recent error to the snapshot
    /// path. Best-effort — if the write fails we just miss this one
    /// update; the next error will try again. Silent failure here is
    /// acceptable because the error we're tracking is already logged
    /// to os_log.
    private func writeSnapshot() {
        let payload: [String: Any] = [
            "alert_insert_errors": alertInsertErrors,
            "event_insert_errors": eventInsertErrors,
            "last_error_message": lastErrorMessage,
            "last_error_kind": lastErrorKind,
            "last_error_at_unix": lastErrorAt?.timeIntervalSince1970 ?? 0,
        ]
        guard let data = try? JSONSerialization.data(
            withJSONObject: payload,
            options: [.prettyPrinted, .sortedKeys]
        ) else { return }
        try? data.write(to: URL(fileURLWithPath: snapshotPath))
    }
}
