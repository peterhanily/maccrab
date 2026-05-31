// NotificationOutput.swift
// MacCrabCore
//
// Sends macOS native notifications for security alerts. The daemon
// runs without a UI bundle, so neither NSUserNotificationCenter
// (deprecated) nor UNUserNotificationCenter (requires the bundle's
// notification entitlement) is reachable. Implementation shells out
// to `osascript -e 'display notification …'` instead. Cheap for the
// notification rate we run at; trades feature surface (custom
// actions, attachments, identifiers) for working-without-bundle.

import Foundation
import os.log

/// Delivers security alerts as macOS notification banners.
///
/// Filters by severity — only high and critical alerts produce notifications
/// by default. Includes rate limiting to prevent notification storms.
public actor NotificationOutput {

    private let logger = Logger(subsystem: "com.maccrab", category: "notifications")

    /// Minimum severity to trigger a notification.
    public var minimumSeverity: Severity

    /// v1.11.0 RC2 (audit functionality MEDIUM): hard mute switch
    /// independent of minimumSeverity. Pre-fix `enabled=false` in
    /// alert_notifications.json was mapped to `Severity.critical`,
    /// which still passed critical alerts through (since `.critical`
    /// is the highest level the gate `>= minimumSeverity` allows).
    /// The user expectation is "off = NO notifications". This flag
    /// short-circuits `notify` regardless of severity.
    public var enabled: Bool = true

    public func setEnabled(_ value: Bool) {
        self.enabled = value
    }

    // v1.17: critical alerts always notify at their true severity. The
    // earlier rc.14 `allowCritical` clamp (which down-rendered criticals
    // to .high unless a Settings toggle was on) was removed — it was a
    // presentation-only control that read like a firing gate and confused
    // operators. The `>= minimumSeverity` gate in notify() is now the only
    // notification filter; banners use the alert's real severity.

    /// Maximum notifications per minute (rate limiting).
    private let maxPerMinute: Int
    private var recentTimestamps: [Date] = []

    /// Track recently notified rule+process combos to avoid duplicates.
    /// Map key → last-notified timestamp so individual keys expire on their
    /// own schedule rather than everything being wiped at once. The prior
    /// implementation cleared the whole set every 5 min, so a persistent
    /// condition (e.g. binary-integrity failure on every 15-second poll)
    /// produced a fresh OS banner every 5 min. Per-key expiry keeps the
    /// first notification and then goes silent for the full window.
    private var recentKeys: [String: Date] = [:]
    private let dedupeWindow: TimeInterval = 3600 // 1 hour

    /// Count of alerts suppressed by rate limiting since the last summary notification.
    private var rateLimitedCount: Int = 0
    /// Whether a rate-limit summary notification has been sent this window.
    private var rateLimitNotified: Bool = false

    /// v1.11.0 (audit functionality HIGH): mutate via this method
    /// from outside the actor (SIGHUP reload path). Direct
    /// `notifier.minimumSeverity = …` is rejected by Swift 6 strict
    /// actor isolation when the caller isn't the same actor.
    public func setMinimumSeverity(_ value: Severity) {
        self.minimumSeverity = value
    }

    public init(minimumSeverity: Severity = .critical, maxPerMinute: Int = 10) {
        self.minimumSeverity = minimumSeverity
        self.maxPerMinute = maxPerMinute
    }

    /// Send a notification for an alert if it passes severity and rate filters.
    public func notify(alert: Alert) {
        // v1.11.0 RC2: hard mute when the user toggled OFF in
        // SettingsView (writes enabled=false to alert_notifications.json).
        guard enabled else { return }
        // Gate on the alert's severity: a min-severity of "critical"
        // suppresses high/medium/low; "high" lets high+critical through;
        // etc. Banners render at the alert's true severity.
        guard alert.severity >= minimumSeverity else { return }
        let displaySeverity = alert.severity

        // Rate limit
        let now = Date()
        recentTimestamps = recentTimestamps.filter { now.timeIntervalSince($0) < 60 }
        if recentTimestamps.count >= maxPerMinute {
            rateLimitedCount += 1
            // Send a single summary notification the first time we hit the limit
            if !rateLimitNotified {
                rateLimitNotified = true
                deliverRateLimitNotification()
            }
            logger.warning("Notification rate limit reached (\(self.maxPerMinute)/min) — \(self.rateLimitedCount) alerts suppressed")
            return
        }

        // Reset rate-limit tracking when we're under the limit again
        if rateLimitNotified && recentTimestamps.count < maxPerMinute / 2 {
            if rateLimitedCount > 0 {
                logger.info("Rate limit window ended. \(self.rateLimitedCount) notifications were suppressed.")
            }
            rateLimitedCount = 0
            rateLimitNotified = false
        }

        // Deduplicate. Key incorporates rule + process path so an attack
        // from the same binary firing multiple rules still notifies for
        // each distinct rule, but a single rule re-firing repeatedly
        // doesn't produce a banner storm.
        let key = "\(alert.ruleId):\(alert.processPath ?? "")"
        if let last = recentKeys[key], now.timeIntervalSince(last) < dedupeWindow {
            return
        }
        pruneRecentKeysIfNeeded(now: now)
        recentKeys[key] = now
        recentTimestamps.append(now)

        // Build and deliver notification (use display severity so
        // a clamped critical alert reads as high in the banner).
        deliverNotification(alert: alert, displaySeverity: displaySeverity)
    }

    /// Evict dedup entries whose individual windows have expired. Amortized
    /// across calls so a long-running daemon doesn't accumulate unbounded
    /// history — only called when the map crosses a lightweight threshold.
    private func pruneRecentKeysIfNeeded(now: Date) {
        guard recentKeys.count > 256 else { return }
        recentKeys = recentKeys.filter { now.timeIntervalSince($0.value) < dedupeWindow }
    }

    private func deliverRateLimitNotification() {
        Self.sendOsascriptNotification(
            title: "⚠️ \u{1F980} MacCrab: Alert Storm",
            body: "Too many alerts — notifications are being throttled. Check the dashboard for full details.",
            sound: "Sosumi"
        )
    }

    private nonisolated func deliverNotification(alert: Alert, displaySeverity: Severity) {
        let severityEmoji: String
        switch displaySeverity {
        case .critical: severityEmoji = "🔴"
        case .high:     severityEmoji = "🟠"
        case .medium:   severityEmoji = "🟡"
        case .low:      severityEmoji = "🟢"
        case .informational: severityEmoji = "⚪"
        }

        let title = "\(severityEmoji) \u{1F980} MacCrab: \(alert.ruleTitle)"
        let body: String
        if let processName = alert.processName, let techniques = alert.mitreTechniques, !techniques.isEmpty {
            body = "Process: \(processName) — \(techniques)"
        } else if let processName = alert.processName {
            body = "Process: \(processName)"
        } else {
            body = alert.description ?? "Security alert detected"
        }

        Self.sendOsascriptNotification(title: title, body: body, sound: "Purr")
    }

    /// Deliver a notification via osascript. This works without an app bundle
    /// or UNUserNotificationCenter entitlements. After the notification,
    /// activates MacCrab.app so clicking it opens the dashboard.
    private nonisolated static func sendOsascriptNotification(title: String, body: String, sound: String) {
        let escapedTitle = title.replacingOccurrences(of: "\"", with: "\\\"")
        let escapedBody = body.replacingOccurrences(of: "\"", with: "\\\"")
        let script = """
            tell application "System Events"
                display notification "\(escapedBody)" \
                with title "\(escapedTitle)" \
                sound name "\(sound)"
            end tell
            """

        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
        process.arguments = ["-e", script]
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        try? process.run()
    }
}
