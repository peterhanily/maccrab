// NotificationOutput.swift
// MacCrabCore
//
// Daemon-side notification gate. Historically this delivered macOS
// banners by shelling out to `osascript -e 'display notification …'`
// (the daemon has no UI bundle, so UNUserNotificationCenter is
// unreachable from here). As of v1.17 (GitHub issue #2) DELIVERY moved
// to the signed app (MacCrabApp/AlertNotifier via UNUserNotificationCenter)
// so banners are attributed to MacCrab and stop on uninstall; this type
// now only runs the shared NotificationGate for diagnostic logging.

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

    /// Evaluate an alert against the notification gate.
    ///
    /// v1.17 (GitHub issue #2): the daemon no longer DELIVERS OS
    /// notifications. Delivery moved to the signed app
    /// (MacCrabApp/AlertNotifier, UNUserNotificationCenter) so banners
    /// are attributed to MacCrab — controllable in System Settings and
    /// gone on uninstall — instead of the old `osascript → System Events`
    /// path, which mis-attributed banners and let them outlive an
    /// uninstall. The osascript spawn (and its AppleScript-injection
    /// surface) is removed entirely. We still run the gate so the
    /// would-notify decision is visible in the daemon log for diagnostics.
    public func notify(alert: Alert) {
        switch gate.evaluate(alert: alert) {
        case .deliver:
            logger.debug("alert passes notification gate (delivered by app): \(alert.ruleId, privacy: .public)")
        case .stormSummary:
            logger.warning("Notification rate limit reached — \(self.gate.suppressedByRateLimit) alerts suppressed")
        case .drop:
            break
        }
    }
}
