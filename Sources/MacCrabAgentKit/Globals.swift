import Foundation
import os.log
import MacCrabCore

/// Shared logger for the daemon process.
let logger = Logger(subsystem: "com.maccrab.agent", category: "main")

/// Track and throttle storage error logging to avoid log spam on persistent failures.
actor StorageErrorTracker {
    static let shared = StorageErrorTracker()
    private var alertInsertErrors: Int = 0
    private var eventInsertErrors: Int = 0
    private var lastAlertErrorLog: Date = .distantPast
    private var lastEventErrorLog: Date = .distantPast

    func recordAlertError(_ error: Error) {
        alertInsertErrors += 1
        // Log at most once per 60 seconds to avoid spam on disk-full scenarios.
        // Error description is marked .public so `sudo log show` on a user
        // machine can reveal the real SQLite error — otherwise Foundation
        // redacts the interpolation as "<private>" and operators diagnosing
        // a broken install can't see what's actually wrong. The error text
        // never contains user secrets (it's SQLite return codes, paths, and
        // filesystem error strings), so .public is safe here.
        if Date().timeIntervalSince(lastAlertErrorLog) > 60 {
            let count = self.alertInsertErrors
            logger.error("Alert insert failed (\(count, privacy: .public) total): \(error.localizedDescription, privacy: .public)")
            lastAlertErrorLog = Date()
        }
    }

    func recordEventError(_ error: Error) {
        eventInsertErrors += 1
        if Date().timeIntervalSince(lastEventErrorLog) > 60 {
            let count = self.eventInsertErrors
            logger.error("Event insert failed (\(count, privacy: .public) total): \(error.localizedDescription, privacy: .public)")
            lastEventErrorLog = Date()
        }
    }
}
