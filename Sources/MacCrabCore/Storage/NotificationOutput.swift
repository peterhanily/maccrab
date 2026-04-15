// NotificationOutput.swift
// MacCrabCore
//
// Sends macOS native notifications for security alerts.
// Uses NSUserNotificationCenter (works without app bundle / UNUserNotificationCenter entitlement).

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

    /// Maximum notifications per minute (rate limiting).
    private let maxPerMinute: Int
    private var recentTimestamps: [Date] = []

    /// Track recently notified rule+process combos to avoid duplicates.
    private var recentKeys: Set<String> = []
    private var lastKeySweep = Date()
    private let dedupeWindow: TimeInterval = 300 // 5 minutes

    /// Count of alerts suppressed by rate limiting since the last summary notification.
    private var rateLimitedCount: Int = 0
    /// Whether a rate-limit summary notification has been sent this window.
    private var rateLimitNotified: Bool = false

    public init(minimumSeverity: Severity = .high, maxPerMinute: Int = 10) {
        self.minimumSeverity = minimumSeverity
        self.maxPerMinute = maxPerMinute
    }

    /// Send a notification for an alert if it passes severity and rate filters.
    public func notify(alert: Alert) {
        guard alert.severity >= minimumSeverity else { return }

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

        // Deduplicate
        let key = "\(alert.ruleId):\(alert.processPath ?? "")"
        sweepKeysIfNeeded(now: now)
        guard !recentKeys.contains(key) else { return }
        recentKeys.insert(key)
        recentTimestamps.append(now)

        // Build and deliver notification
        deliverNotification(alert: alert)
    }

    private func sweepKeysIfNeeded(now: Date) {
        if now.timeIntervalSince(lastKeySweep) > dedupeWindow {
            recentKeys.removeAll()
            lastKeySweep = now
        }
    }

    private func deliverRateLimitNotification() {
        Self.sendOsascriptNotification(
            title: "⚠️ \u{1F980} MacCrab: Alert Storm",
            body: "Too many alerts — notifications are being throttled. Check the dashboard for full details.",
            sound: "Sosumi"
        )
    }

    private nonisolated func deliverNotification(alert: Alert) {
        let severityEmoji: String
        switch alert.severity {
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
