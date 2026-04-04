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
        guard recentTimestamps.count < maxPerMinute else {
            logger.warning("Notification rate limit reached (\(self.maxPerMinute)/min)")
            return
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

    private nonisolated func deliverNotification(alert: Alert) {
        let severityEmoji: String
        switch alert.severity {
        case .critical: severityEmoji = "🔴"
        case .high:     severityEmoji = "🟠"
        case .medium:   severityEmoji = "🟡"
        case .low:      severityEmoji = "🟢"
        case .informational: severityEmoji = "⚪"
        }

        let title = "\(severityEmoji) MacCrab: \(alert.ruleTitle)"
        let body: String
        if let processName = alert.processName, let techniques = alert.mitreTechniques, !techniques.isEmpty {
            body = "Process: \(processName) — \(techniques)"
        } else if let processName = alert.processName {
            body = "Process: \(processName)"
        } else {
            body = alert.description ?? "Security alert detected"
        }

        // Use osascript for reliable notification delivery from CLI daemons.
        // NSUserNotificationCenter requires an app bundle; UNUserNotificationCenter
        // requires entitlements. osascript works universally.
        let script = """
            display notification "\(body.replacingOccurrences(of: "\"", with: "\\\""))" \
            with title "\(title.replacingOccurrences(of: "\"", with: "\\\""))" \
            sound name "Purr"
            """

        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
        process.arguments = ["-e", script]
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice

        do {
            try process.run()
        } catch {
            logger.error("Failed to deliver notification: \(error.localizedDescription)")
        }
    }
}
