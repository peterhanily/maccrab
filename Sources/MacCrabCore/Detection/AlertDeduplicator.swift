// AlertDeduplicator.swift
// MacCrabCore
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
        subsystem: "com.maccrab.detection",
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
            ruleStats[ruleId, default: (emitted: 0, suppressed: 0)].suppressed += 1
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
        ruleStats[ruleId, default: (emitted: 0, suppressed: 0)].emitted += 1

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

    // MARK: - FP Rate Tracking

    /// Per-rule suppression rate for environment-aware FP scoring.
    /// Tracks (emitted, suppressed) counts to compute FP rates.
    private var ruleStats: [String: (emitted: Int, suppressed: Int)] = [:]

    /// Returns the suppression rate for a rule (0.0-1.0).
    /// High rates (>0.5) suggest the rule is noisy in this environment.
    public func suppressionRate(forRule ruleId: String) -> Double {
        guard let stats = ruleStats[ruleId] else { return 0 }
        let total = stats.emitted + stats.suppressed
        guard total > 10 else { return 0 } // Need at least 10 observations
        return Double(stats.suppressed) / Double(total)
    }

    /// Returns rules with suppression rates above a threshold.
    public func noisyRules(threshold: Double = 0.5) -> [(ruleId: String, rate: Double, total: Int)] {
        ruleStats.compactMap { (ruleId, stats) in
            let total = stats.emitted + stats.suppressed
            guard total > 10 else { return nil }
            let rate = Double(stats.suppressed) / Double(total)
            guard rate >= threshold else { return nil }
            return (ruleId: ruleId, rate: rate, total: total)
        }.sorted { $0.rate > $1.rate }
    }

    // MARK: - User-Dismissal Feedback

    /// Per-rule user-dismissal counts. Tracked separately from
    /// internal dedup-driven suppression: a user actively clicking "suppress"
    /// in the UI is a much stronger signal than the in-memory dedup window
    /// firing. Used by the event loop to auto-downgrade severity on rules
    /// the operator keeps flagging as false positives.
    private var dismissalCounts: [String: Int] = [:]
    /// Alert IDs we have already processed for feedback, so the periodic
    /// sweep from the database doesn't double-count the same dismissal.
    private var processedDismissals: Set<String> = []

    /// Record a user-initiated dismissal of an alert. Idempotent on
    /// `alertId` — safe to call from a periodic sweep.
    public func recordDismissal(alertId: String, ruleId: String) {
        guard !processedDismissals.contains(alertId) else { return }
        processedDismissals.insert(alertId)
        dismissalCounts[ruleId, default: 0] += 1
    }

    /// Total user-dismissals for a rule since daemon start.
    public func dismissalCount(forRule ruleId: String) -> Int {
        dismissalCounts[ruleId] ?? 0
    }

    /// Fraction of emitted alerts the user has dismissed (0.0-1.0).
    /// Needs at least 3 dismissals before returning a non-zero rate — one
    /// dismissal isn't enough signal to auto-tune on.
    public func dismissalRate(forRule ruleId: String) -> Double {
        let dismissals = dismissalCounts[ruleId] ?? 0
        guard dismissals >= 3 else { return 0 }
        let emitted = ruleStats[ruleId]?.emitted ?? 0
        let denom = max(emitted, dismissals)
        return Double(dismissals) / Double(denom)
    }

    /// Auto-downgrade severity for rules the user keeps dismissing. Never
    /// returns a value higher than the input severity, and never downgrades
    /// below `.medium` — something the user dismisses repeatedly is still
    /// worth logging, just not flashing a notification.
    public func effectiveSeverity(ruleId: String, original: Severity) -> Severity {
        // Critical stays critical. The user shouldn't be able to turn off
        // ransomware/SIP-disabled alerts by muting their dashboard.
        if original == .critical { return original }
        let rate = dismissalRate(forRule: ruleId)
        if rate >= 0.7 {
            // Very noisy in this environment: push down one level.
            switch original {
            case .high:   return .medium
            case .medium: return .low
            case .low, .informational, .critical: return original
            }
        }
        return original
    }

    /// Bound the processed-dismissal set so it doesn't grow without limit
    /// across a long-running daemon.
    public func prunePrcessedDismissals(keepingLast limit: Int = 50_000) {
        guard processedDismissals.count > limit else { return }
        // Rebuild as a fresh, empty set — feedback for long-gone alerts is no
        // longer relevant, and the next sweep will re-populate with current
        // dismissals.
        processedDismissals.removeAll(keepingCapacity: false)
    }

    // MARK: - Private Helpers

    /// Builds the deduplication key from rule ID and process path.
    /// Uses path normalization to group similar paths (strips versions, UUIDs, temp suffixes).
    private func makeKey(ruleId: String, processPath: String) -> String {
        "\(ruleId):\(normalizePath(processPath))"
    }

    /// Normalize a process path for fuzzy deduplication.
    /// Strips version numbers, UUIDs, and temp path components so that
    /// /tmp/build-12345/binary and /tmp/build-67890/binary deduplicate.
    private func normalizePath(_ path: String) -> String {
        var normalized = path
        // Strip UUIDs
        normalized = normalized.replacingOccurrences(
            of: #"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"#,
            with: "*", options: .regularExpression
        )
        // Strip version-like segments embedded in the path (e.g., /1.2.3/, /v2.0/)
        normalized = normalized.replacingOccurrences(
            of: #"/v?\d+\.\d+(\.\d+)*/"#,
            with: "/*/", options: .regularExpression
        )
        // Strip version-like segments at the END of the path (e.g.,
        // ".../versions/2.1.111" or ".../foo-v1.2"). Without this,
        // auto-updating tools like Claude Code re-fire the behavioral
        // composite alert on every version bump because the key is
        // uniquely different per release.
        normalized = normalized.replacingOccurrences(
            of: #"/v?\d+\.\d+(\.\d+)*$"#,
            with: "/*", options: .regularExpression
        )
        // Strip numeric temp path segments (e.g., /build-12345/, /tmp-9999/)
        normalized = normalized.replacingOccurrences(
            of: #"/[a-zA-Z]+-\d{4,}/"#,
            with: "/*/", options: .regularExpression
        )
        return normalized
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
