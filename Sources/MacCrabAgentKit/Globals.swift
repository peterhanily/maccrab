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
///
/// v1.12.6 Wave 9D: escalate silent insert failures.
///
/// The v1.4.3 design throttled to one log line per 60s globally, which
/// collapsed onto a single message under a sustained failure flood:
/// a user filled their disk and lost 102,234 events while the log
/// surface emitted ~30 lines, all generic "disk I/O error". The
/// dashboard never raised a banner because the JSON snapshot file
/// counters incremented but no consumer correlated rate-of-growth.
///
/// Wave 9D adds three escalation tiers without changing the existing
/// per-error-write contract:
///
///   - Tier 1: per-kind logarithmic emission. The first failure of
///     a kind (e.g. "disk I/O error", "constraint failed") logs once;
///     subsequent failures of the same kind log at 10, 100, 1000,
///     10000. Cross-kind interference is removed — each kind has its
///     own logarithmic ladder.
///   - Tier 2: rate-warning. If event-insert errors grow by > 100
///     in a 60-second rolling window we emit `logger.warning` with
///     the rate + total. Reset after each emission to one-per-minute
///     max.
///   - Tier 3: heartbeat surface. The 30 s heartbeat writer reads
///     `eventInsertErrorSnapshot()` and surfaces total + per-minute
///     rate + last-kind into `heartbeat_rich.json` so the dashboard
///     can render a "storage degraded" banner without needing to
///     poll `storage_errors.json` separately.
actor StorageErrorTracker {
    static let shared = StorageErrorTracker()
    private var alertInsertErrors: Int = 0
    private var eventInsertErrors: Int = 0
    private var lastErrorMessage: String = ""
    /// Legacy field surfaced into `storage_errors.json` as
    /// `last_error_kind`. Value vocabulary is unchanged from v1.4.3
    /// — `"alert_insert"` or `"event_insert"` (or empty before any
    /// error). The Wave 9D per-kind classification lives separately
    /// in `lastEventInsertKind` so the legacy snapshot file's
    /// contract stays intact for dashboard consumers.
    private var lastErrorKind: String = ""
    /// Wave 9D: normalised event-insert error kind (e.g. `disk_io`,
    /// `constraint`, `lock_timeout`). Surfaces into `heartbeat_rich.
    /// json` as `last_event_insert_error_kind` and drives Tier 1's
    /// per-kind escalation ladder. Empty string when no event-insert
    /// error has been recorded since boot.
    private var lastEventInsertKind: String = ""
    private var lastErrorAt: Date?

    /// Per-kind running totals for event-insert errors. Keys are
    /// normalised error kinds (e.g. `disk_io`, `constraint`).
    /// Bounded to `maxKindEntries` to keep memory flat under a
    /// pathological flood of distinct error strings — we evict the
    /// least-recently-incremented kind. Logarithmic emission decisions
    /// are made off these per-kind totals so an unbounded "other"
    /// bucket can't crowd them out.
    private var eventErrorCountByKind: [String: Int] = [:]
    private var eventErrorLastSeenByKind: [String: Date] = [:]
    /// LRU cap for `eventErrorCountByKind`. SQLite error strings are
    /// from a closed vocabulary (~20 distinct), so 32 leaves comfortable
    /// headroom but bounds worst-case memory.
    private let maxKindEntries: Int = 32

    /// Rolling rate-counter window for Tier 2. Holds the per-second
    /// bucket count of event-insert errors during the trailing minute,
    /// keyed by Unix-epoch second. Older buckets are evicted on each
    /// record. Memory bounded at 60 entries.
    private var eventErrorPerSecondWindow: [Int64: Int] = [:]
    private var lastRateWarningAt: Date = .distantPast
    /// Tier 2 threshold: more than this many event-insert errors in
    /// the trailing 60s emits a single `logger.warning`. 100/minute is
    /// well above any normal hiccup (transient SQLITE_BUSY on contention)
    /// and well below a sustained-failure rate.
    private let rateWarningThreshold: Int = 100
    /// Tier 2 cooldown: at most one rate warning per minute regardless
    /// of how high the rate climbs. Prevents log spam if a flood
    /// continues — Tier 1's logarithmic ladder still captures
    /// continued growth.
    private let rateWarningCooldown: TimeInterval = 60

    /// Test-observable emission counters. Production code never reads
    /// these; tests use them to assert the escalation ladder fired
    /// the expected number of times without needing to mock os_log.
    internal var tier1EmissionCount: Int = 0
    internal var tier2EmissionCount: Int = 0
    /// Per-kind tier-1 emission ladder positions so tests can verify
    /// kinds escalate independently.
    internal var tier1EmissionsByKind: [String: Int] = [:]

    /// Well-known path the dashboard polls. Sits alongside the DB in
    /// `/Library/Application Support/MacCrab/` so file permissions
    /// match the rest of the managed-state tree: sysext (root)
    /// writes, non-root dashboard reads.
    private let snapshotPath = "/Library/Application Support/MacCrab/storage_errors.json"

    /// Alert insert error path. v1.12.6 Wave 9D leaves this on the
    /// legacy 60-second throttle — the escalation work targets the
    /// event-insert path that overwhelmed the user's machine. The
    /// alert path has a much lower steady-state volume; if it also
    /// needs per-kind escalation we can mirror the event-side logic
    /// in a follow-up wave.
    private var lastAlertErrorLog: Date = .distantPast

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
        recordEventError(error, now: Date())
    }

    /// Clock-injectable overload used by tests to drive the rate
    /// window deterministically. Production callers go through the
    /// no-`now` form above.
    internal func recordEventError(_ error: Error, now: Date) {
        eventInsertErrors += 1
        let message = error.localizedDescription
        lastErrorMessage = message
        let kind = Self.classifyEventInsertError(error)
        // Legacy snapshot keeps the coarse "event_insert" sentinel so
        // `storage_errors.json` consumers (AppState.refreshStorageHealth
        // and the dashboard banner gate) see the same value vocabulary
        // they've had since v1.4.3. The new fine-grained kind goes to
        // the heartbeat via `lastEventInsertKind`.
        lastErrorKind = "event_insert"
        lastEventInsertKind = kind
        lastErrorAt = now

        // Tier 1: per-kind logarithmic emission. Increment the kind's
        // running total, then log if the new total crosses one of the
        // 10^N thresholds. Distinct kinds escalate independently.
        let newCountForKind = recordKindHit(kind, at: now)
        if shouldEmitTier1(forCountAfterIncrement: newCountForKind) {
            tier1EmissionCount &+= 1
            tier1EmissionsByKind[kind, default: 0] &+= 1
            logger.error(
                "Event insert failure: kind=\(kind, privacy: .public) kind_count=\(newCountForKind, privacy: .public) total=\(self.eventInsertErrors, privacy: .public) msg=\(message, privacy: .public)"
            )
        }

        // Tier 2: rate-window warning. Record this error in the
        // per-second window; if the trailing minute exceeds the
        // threshold and we're outside the cooldown, emit one warning.
        recordRateHit(at: now)
        evictExpiredRateBuckets(now: now)
        let rate = currentRatePerMinute()
        if rate > rateWarningThreshold, now.timeIntervalSince(lastRateWarningAt) >= rateWarningCooldown {
            tier2EmissionCount &+= 1
            lastRateWarningAt = now
            logger.warning(
                "Event insert failure rate elevated: \(rate, privacy: .public)/min over trailing 60s (total=\(self.eventInsertErrors, privacy: .public), last_kind=\(kind, privacy: .public))"
            )
        }

        writeSnapshot()
    }

    /// Tier 3 surface — read by `DaemonTimers` when assembling the
    /// rich heartbeat payload. Returns a triple (total, per-minute
    /// rate, last-kind) suitable for direct JSON encoding. The
    /// heartbeat path runs on a 30 s cadence, so reading this is
    /// strictly off the hot insert path.
    ///
    /// `lastKind` is `nil` when no event-insert error has been
    /// recorded since boot. The heartbeat reader treats `nil`
    /// as "no recent event-insert failure" — the count + rate fields
    /// remain authoritative on their own.
    public func eventInsertErrorSnapshot(now: Date = Date()) -> (total: Int, ratePerMin: Int, lastKind: String?) {
        evictExpiredRateBuckets(now: now)
        let rate = currentRatePerMinute()
        let lastKind: String? = lastEventInsertKind.isEmpty ? nil : lastEventInsertKind
        return (eventInsertErrors, rate, lastKind)
    }

    /// Test-only: reset all internal state. Production never calls this
    /// because the tracker is a singleton owned for the daemon's lifetime.
    internal func resetForTesting() {
        alertInsertErrors = 0
        eventInsertErrors = 0
        lastErrorMessage = ""
        lastErrorKind = ""
        lastEventInsertKind = ""
        lastErrorAt = nil
        eventErrorCountByKind.removeAll()
        eventErrorLastSeenByKind.removeAll()
        eventErrorPerSecondWindow.removeAll()
        lastRateWarningAt = .distantPast
        lastAlertErrorLog = .distantPast
        tier1EmissionCount = 0
        tier2EmissionCount = 0
        tier1EmissionsByKind.removeAll()
    }

    // MARK: - Internal helpers

    /// Map an `EventStoreError` (or any caller-supplied error) to a
    /// compact, normalised kind string. The kind is what drives Tier 1
    /// per-kind escalation and surfaces into heartbeat as
    /// `last_event_insert_error_kind`.
    ///
    /// Order matters here: SQLite step failures embed the underlying
    /// errno in their string body, so we inspect the message before
    /// falling back to the enum case.
    internal static func classifyEventInsertError(_ error: Error) -> String {
        let raw = error.localizedDescription
        let lower = raw.lowercased()
        // Closed-vocabulary SQLite kinds, ordered by specificity. The
        // user's field report (`Step failed: disk I/O error`, 102234
        // occurrences) maps to `disk_io` here.
        if lower.contains("disk i/o error") || lower.contains("disk io error") || lower.contains("ioerr") {
            return "disk_io"
        }
        if lower.contains("database or disk is full") || lower.contains("disk full") || lower.contains("sqlite_full") {
            return "disk_full"
        }
        if lower.contains("database is locked") || lower.contains("database table is locked") || lower.contains("sqlite_busy") || lower.contains("sqlite_locked") || lower.contains("lock") {
            return "lock_timeout"
        }
        if lower.contains("constraint") {
            return "constraint"
        }
        if lower.contains("readonly") || lower.contains("read-only") {
            return "readonly"
        }
        if lower.contains("out of memory") || lower.contains("nomem") {
            return "out_of_memory"
        }
        if lower.contains("corrupt") || lower.contains("not a database") {
            return "corrupt"
        }
        if lower.contains("encoding failed") {
            return "encoding"
        }
        if lower.contains("prepare failed") {
            return "prepare"
        }
        if lower.contains("step failed") {
            return "step_other"
        }
        return "other"
    }

    /// Record a hit against the per-kind ledger and return the new
    /// count for that kind. Honours the LRU cap (`maxKindEntries`) so
    /// a pathological flood of unique error strings can't grow the
    /// map without bound.
    private func recordKindHit(_ kind: String, at now: Date) -> Int {
        if eventErrorCountByKind[kind] == nil, eventErrorCountByKind.count >= maxKindEntries {
            // Evict the least-recently-seen kind. We're already in a
            // failure path so the O(n) scan over <= 32 entries is fine.
            if let oldest = eventErrorLastSeenByKind.min(by: { $0.value < $1.value })?.key {
                eventErrorCountByKind.removeValue(forKey: oldest)
                eventErrorLastSeenByKind.removeValue(forKey: oldest)
            }
        }
        let next = (eventErrorCountByKind[kind] ?? 0) + 1
        eventErrorCountByKind[kind] = next
        eventErrorLastSeenByKind[kind] = now
        return next
    }

    /// Logarithmic emission ladder: emit at 1, 10, 100, 1_000, 10_000,
    /// 100_000. Tested against the user's 102K-event flood to bound
    /// log volume at ~5 lines per kind instead of ~100K.
    private func shouldEmitTier1(forCountAfterIncrement count: Int) -> Bool {
        guard count > 0 else { return false }
        if count == 1 { return true }
        // Powers of ten up to 10^6 cover every realistic field count.
        var threshold = 10
        while threshold <= 1_000_000 {
            if count == threshold { return true }
            threshold *= 10
        }
        return false
    }

    /// Bucket the current second's hit into the rolling window.
    /// Uses integer Unix-epoch seconds as the bucket key so all
    /// hits within the same wall-clock second collapse into one
    /// dict entry — bounded memory regardless of error frequency.
    private func recordRateHit(at now: Date) {
        let bucket = Int64(now.timeIntervalSince1970)
        eventErrorPerSecondWindow[bucket, default: 0] &+= 1
    }

    /// Drop any per-second buckets older than 60 s. Called from
    /// both `recordEventError` (so the window only ever holds a
    /// minute of data, even between heartbeats) and the heartbeat
    /// snapshot path (so a quiet minute reports 0 rather than a
    /// stale value).
    private func evictExpiredRateBuckets(now: Date) {
        let cutoff = Int64(now.timeIntervalSince1970) - 60
        eventErrorPerSecondWindow = eventErrorPerSecondWindow.filter { $0.key > cutoff }
    }

    /// Sum the per-second window. Cheap (<= 60 entries) and stays
    /// off the SQLite insert path. The caller must invoke
    /// `evictExpiredRateBuckets(now:)` first; we keep these two
    /// concerns separate so tests can assert the window contents
    /// without re-evicting.
    private func currentRatePerMinute() -> Int {
        return eventErrorPerSecondWindow.values.reduce(0, +)
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
