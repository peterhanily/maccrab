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

    /// Shared decision logic (severity floor, enabled mute, rate limit,
    /// dedup). The app's AlertNotifier uses the same type so the two
    /// posters can't diverge. See NotificationGate.
    private var gate: NotificationGate

    // v1.17: critical alerts always notify at their true severity. The
    // earlier rc.14 `allowCritical` clamp was removed — it was a
    // presentation-only control that read like a firing gate. The
    // `>= minimumSeverity` gate is now the only notification filter.

    public func setEnabled(_ value: Bool) {
        gate.enabled = value
    }

    /// v1.11.0 (audit functionality HIGH): mutate via this method
    /// from outside the actor (SIGHUP reload path). Direct
    /// property mutation is rejected by Swift 6 strict actor isolation.
    public func setMinimumSeverity(_ value: Severity) {
        gate.minimumSeverity = value
    }

    public init(minimumSeverity: Severity = .critical, maxPerMinute: Int = 10) {
        self.gate = NotificationGate(minimumSeverity: minimumSeverity, maxPerMinute: maxPerMinute)
    }

    /// Send a notification for an alert if it passes the shared gate.
    public func notify(alert: Alert) {
        switch gate.evaluate(alert: alert) {
        case .deliver(let title, let body, let sound):
            Self.sendOsascriptNotification(title: title, body: body, sound: sound)
        case .stormSummary(let title, let body, let sound):
            logger.warning("Notification rate limit reached — \(self.gate.suppressedByRateLimit) alerts suppressed")
            Self.sendOsascriptNotification(title: title, body: body, sound: sound)
        case .drop:
            break
        }
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
