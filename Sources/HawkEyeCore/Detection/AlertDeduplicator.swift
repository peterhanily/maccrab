// AlertDeduplicator.swift
// HawkEyeCore
//
// Prevents alert fatigue by suppressing duplicate alerts within a configurable
// time window. Keyed on ruleId + processPath so the same rule firing for the
// same binary is only surfaced once per suppression interval.

import Foundation
import os.log

// MARK: - AlertDeduplicator

/// Suppresses duplicate alerts so operators are not overwhelmed by high-volume,
/// repetitive detections.
///
/// The deduplicator maintains an in-memory table of recently emitted alerts,
/// keyed by `ruleId:processPath`. When a new alert arrives for a key that was
/// already emitted within the suppression window, it is silently dropped and
/// the suppressed count is incremented. Callers should periodically invoke
/// ``sweep()`` to evict expired entries and bound memory usage.
///
/// Thread-safe via Swift actor isolation.
public actor AlertDeduplicator {

    // MARK: Types

    /// Tracks the timing and suppression count for a single deduplication key.
    struct DeduplicationEntry {
        /// Timestamp of the most recent alert that was actually emitted.
        var lastAlertTime: Date
        /// Number of duplicate alerts suppressed since the last emission.
        var suppressedCount: Int
        /// When the first alert for this key was recorded.
        let firstSeen: Date
    }

    // MARK: Properties

    /// Active deduplication entries keyed by "\(ruleId):\(processPath)".
    private var entries: [String: DeduplicationEntry] = [:]

    /// Duration (in seconds) after an alert emission during which duplicates
    /// are suppressed. Defaults to 3600 (one hour).
    private var suppressionWindow: TimeInterval

    /// Upper bound on the number of tracked keys. When exceeded, ``sweep()``
    /// removes expired entries. If still over the limit, the oldest entries
    /// are evicted.
    private var maxEntries: Int = 10_000

    private let logger = Logger(
        subsystem: "com.hawkeye.detection",
        category: "AlertDeduplicator"
    )

    // MARK: Initialization

    /// Creates a deduplicator with the given suppression window.
    ///
    /// - Parameter suppressionWindow: Seconds to suppress duplicates after an
    ///   alert is emitted. Defaults to 3600 (one hour).
    public init(suppressionWindow: TimeInterval = 3600) {
        self.suppressionWindow = suppressionWindow
    }

    // MARK: - Public API

    /// Determines whether an alert for the given rule and process should be
    /// suppressed.
    ///
    /// Returns `true` when a matching entry exists whose ``lastAlertTime`` falls
    /// within the suppression window, meaning the caller should drop the alert.
    /// The entry's ``suppressedCount`` is incremented automatically.
    ///
    /// Returns `false` when the alert is new or the previous window has expired,
    /// meaning the caller should emit the alert and then call ``recordAlert(ruleId:processPath:)``.
    ///
    /// - Parameters:
    ///   - ruleId: The identifier of the detection rule that fired.
    ///   - processPath: The executable path of the process that triggered the alert.
    /// - Returns: `true` if the alert is a duplicate and should be suppressed.
    public func shouldSuppress(ruleId: String, processPath: String) -> Bool {
        let key = makeKey(ruleId: ruleId, processPath: processPath)
        let now = Date()

        guard let entry = entries[key] else {
            // Never seen before -- do not suppress.
            return false
        }

        let elapsed = now.timeIntervalSince(entry.lastAlertTime)
        if elapsed < suppressionWindow {
            // Within the suppression window -- suppress and count.
            entries[key]?.suppressedCount += 1
            let count = self.entries[key]?.suppressedCount ?? 0
            logger.debug(
                "Suppressed duplicate alert for \(key, privacy: .public) (count: \(count))"
            )
            return true
        }

        // Window has expired -- allow through.
        return false
    }

    /// Records that an alert was emitted, creating or resetting the entry for
    /// the given key.
    ///
    /// Call this immediately after emitting an alert that was *not* suppressed.
    ///
    /// - Parameters:
    ///   - ruleId: The identifier of the detection rule that fired.
    ///   - processPath: The executable path of the process that triggered the alert.
    public func recordAlert(ruleId: String, processPath: String) {
        let key = makeKey(ruleId: ruleId, processPath: processPath)
        let now = Date()

        if let existing = entries[key] {
            // Reset window, keep firstSeen.
            if existing.suppressedCount > 0 {
                logger.info(
                    "Re-emitting alert for \(key, privacy: .public) after \(existing.suppressedCount) suppressed duplicates"
                )
            }
            entries[key] = DeduplicationEntry(
                lastAlertTime: now,
                suppressedCount: 0,
                firstSeen: existing.firstSeen
            )
        } else {
            entries[key] = DeduplicationEntry(
                lastAlertTime: now,
                suppressedCount: 0,
                firstSeen: now
            )
        }

        // Enforce max entries when we cross the threshold.
        if entries.count > maxEntries {
            sweep()
            evictOldestIfNeeded()
        }
    }

    /// Returns aggregate suppression statistics.
    ///
    /// - Returns: A tuple of the number of active suppression entries and the
    ///   total number of alerts that have been suppressed across all keys.
    public func stats() -> (activeSuppressions: Int, totalSuppressed: Int) {
        let totalSuppressed = entries.values.reduce(0) { $0 + $1.suppressedCount }
        return (activeSuppressions: entries.count, totalSuppressed: totalSuppressed)
    }

    /// Removes all deduplication state, allowing all alerts to pass through.
    public func reset() {
        let count = entries.count
        entries.removeAll()
        logger.info("Deduplication state reset (\(count) entries cleared)")
    }

    /// Removes entries whose suppression window has expired.
    ///
    /// Should be called periodically (e.g. on a timer) to keep memory bounded.
    public func sweep() {
        let now = Date()
        var expiredCount = 0

        entries = entries.filter { _, entry in
            let elapsed = now.timeIntervalSince(entry.lastAlertTime)
            if elapsed >= suppressionWindow {
                expiredCount += 1
                return false
            }
            return true
        }

        if expiredCount > 0 {
            logger.info("Swept \(expiredCount) expired deduplication entries")
        }
    }

    // MARK: - Private Helpers

    /// Builds the deduplication key from rule ID and process path.
    private func makeKey(ruleId: String, processPath: String) -> String {
        "\(ruleId):\(processPath)"
    }

    /// If we are still over ``maxEntries`` after sweeping, evict the oldest
    /// entries by ``lastAlertTime`` until we are within limits.
    private func evictOldestIfNeeded() {
        guard entries.count > maxEntries else { return }

        let excess = entries.count - maxEntries
        let sortedKeys = entries
            .sorted { $0.value.lastAlertTime < $1.value.lastAlertTime }
            .prefix(excess)
            .map(\.key)

        for key in sortedKeys {
            entries.removeValue(forKey: key)
        }

        logger.warning("Evicted \(excess) oldest deduplication entries to enforce max capacity")
    }
}
