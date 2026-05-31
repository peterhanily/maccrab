// NotificationGate.swift
// MacCrabCore
//
// Delivery-agnostic decision logic for security-alert notifications:
// the enabled hard-mute, the >= minimumSeverity threshold, a per-minute
// rate limit (with a single "alert storm" summary the first time it
// trips), and 1-hour per-(ruleId:processPath) dedup.
//
// This is shared by the daemon's NotificationOutput and the app's
// AlertNotifier so the two posters can never diverge on what counts as
// a deliverable notification. Callers own their own isolation (the
// daemon wraps it in an actor; the app uses it on @MainActor) and own
// delivery (osascript — being retired — vs UNUserNotificationCenter).

import Foundation

/// What the gate decided for a given alert.
public enum NotificationDecision: Sendable, Equatable {
    /// Deliver a normal alert banner with these strings.
    case deliver(title: String, body: String, sound: String)
    /// Deliver the one-shot "alert storm" summary (the rate limit just
    /// tripped this window); subsequent rate-limited alerts return `.drop`.
    case stormSummary(title: String, body: String, sound: String)
    /// Drop silently — disabled, below the severity floor, deduped, or
    /// rate-limited after the summary already fired.
    case drop
}

/// Stateful gate: feed it alerts in arrival order; it tracks the rate
/// window and dedup map. Not thread-safe on its own — the caller's
/// isolation (actor / @MainActor) provides serialization.
public struct NotificationGate: Sendable {

    /// Hard mute, independent of severity. `false` → every alert drops.
    public var enabled: Bool
    /// Minimum severity that may notify (`alert.severity >= minimumSeverity`).
    public var minimumSeverity: Severity

    public let maxPerMinute: Int
    public let dedupeWindow: TimeInterval

    private var recentTimestamps: [Date] = []
    private var recentKeys: [String: Date] = [:]
    private var rateLimitedCount = 0
    private var rateLimitNotified = false

    public init(minimumSeverity: Severity = .critical,
                enabled: Bool = true,
                maxPerMinute: Int = 10,
                dedupeWindow: TimeInterval = 3600) {
        self.minimumSeverity = minimumSeverity
        self.enabled = enabled
        self.maxPerMinute = maxPerMinute
        self.dedupeWindow = dedupeWindow
    }

    /// Decide whether `alert` should produce a notification, advancing
    /// the rate/dedup state. `now` is injectable for tests.
    public mutating func evaluate(alert: Alert, now: Date = Date()) -> NotificationDecision {
        // Hard mute (user toggled OFF) — short-circuits everything.
        guard enabled else { return .drop }
        // Severity floor; banners render at the alert's true severity.
        guard alert.severity >= minimumSeverity else { return .drop }

        // Rate limit: trim the 60s window first.
        recentTimestamps = recentTimestamps.filter { now.timeIntervalSince($0) < 60 }
        if recentTimestamps.count >= maxPerMinute {
            rateLimitedCount += 1
            if !rateLimitNotified {
                rateLimitNotified = true
                let b = Self.stormBanner()
                return .stormSummary(title: b.title, body: b.body, sound: b.sound)
            }
            return .drop
        }
        // Reset the storm latch once we're well back under the limit.
        if rateLimitNotified && recentTimestamps.count < maxPerMinute / 2 {
            rateLimitedCount = 0
            rateLimitNotified = false
        }

        // Dedup: rule + process so the same binary tripping multiple
        // rules still notifies per rule, but one rule re-firing on a
        // poll loop doesn't storm.
        let key = "\(alert.ruleId):\(alert.processPath ?? "")"
        if let last = recentKeys[key], now.timeIntervalSince(last) < dedupeWindow {
            return .drop
        }
        pruneRecentKeysIfNeeded(now: now)
        recentKeys[key] = now
        recentTimestamps.append(now)

        let b = Self.banner(for: alert)
        return .deliver(title: b.title, body: b.body, sound: b.sound)
    }

    private mutating func pruneRecentKeysIfNeeded(now: Date) {
        guard recentKeys.count > 256 else { return }
        recentKeys = recentKeys.filter { now.timeIntervalSince($0.value) < dedupeWindow }
    }

    /// Number of alerts dropped by the rate limit since the last reset —
    /// for diagnostics/logging by the caller.
    public var suppressedByRateLimit: Int { rateLimitedCount }

    // MARK: - Banner text (pure)

    public static func banner(for alert: Alert) -> (title: String, body: String, sound: String) {
        let emoji: String
        switch alert.severity {
        case .critical:      emoji = "🔴"
        case .high:          emoji = "🟠"
        case .medium:        emoji = "🟡"
        case .low:           emoji = "🟢"
        case .informational: emoji = "⚪"
        }
        let title = "\(emoji) \u{1F980} MacCrab: \(alert.ruleTitle)"
        let body: String
        if let processName = alert.processName, let techniques = alert.mitreTechniques, !techniques.isEmpty {
            body = "Process: \(processName) — \(techniques)"
        } else if let processName = alert.processName {
            body = "Process: \(processName)"
        } else {
            body = alert.description ?? "Security alert detected"
        }
        return (title, body, "Purr")
    }

    public static func stormBanner() -> (title: String, body: String, sound: String) {
        ("⚠️ \u{1F980} MacCrab: Alert Storm",
         "Too many alerts — notifications are being throttled. Check the dashboard for full details.",
         "Sosumi")
    }
}
