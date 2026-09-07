// AlertNotifier.swift
// MacCrabApp
//
// Posts security-alert banners via UNUserNotificationCenter from the
// signed com.maccrab.app bundle, so notifications are attributed to
// **MacCrab** (a controllable row in System Settings > Notifications)
// and stop the moment the app is removed. This replaces the daemon's
// osascript → "System Events" path (GitHub issue #2).
//
// Design (from the v1.17 notification-rearchitecture plan):
//   - Self-contained: its OWN read-only AlertStore handle + its OWN
//     persisted cursor, so it's independent of AppState's scenePhase-
//     gated UI poll. Driven by the AppDelegate process-lifetime timer,
//     it keeps notifying while the dashboard window is closed (it only
//     goes silent when the whole menu-bar app is quit — the same
//     property that makes notifications stop on uninstall).
//   - Shares NotificationGate with the daemon so the two can't diverge.
//   - Honors alert_notifications.json {enabled, min_severity}.
//   - On denied/undetermined authorization, falls back to the in-app
//     popover so the operator is never silently blind.

import Foundation
import AppKit
import UserNotifications
import MacCrabCore
import os.log

@MainActor
final class AlertNotifier: NSObject {

    private let logger = Logger(subsystem: "com.maccrab.app", category: "notifier")
    private let center = UNUserNotificationCenter.current()

    /// Shared decision logic (severity floor, enabled mute, rate limit, dedup).
    private var gate = NotificationGate()
    /// Resolved data dir the daemon writes alerts.db + the config to.
    private let dataDir: String?
    /// Lazily-opened read-only handle to alerts.db.
    private var store: AlertStore?
    /// Timestamp of the newest alert we've already considered. Persisted
    /// so a relaunch doesn't re-notify the backlog.
    private var cursor: Date?
    /// Upgrade-handoff gate. While set to a future date, `tick()` returns
    /// WITHOUT posting or advancing the cursor, so a freshly-launched
    /// post-upgrade app stays silent during the `OSSystemExtensionRequest`
    /// (.replace) window — when the OLD resident sysext (≤v1.17.1) may still
    /// be posting its own osascript banners and the exiting old app process
    /// is briefly co-resident. The AppDelegate arms this on the sysext's
    /// `.activating` transition and clears it on settle. It is an ABSOLUTE
    /// deadline, so posting resumes even if the request never completes —
    /// the gate is fail-open. Not advancing the cursor means alerts that
    /// fired in the window are re-evaluated once it lifts (same discipline
    /// as the `.notDetermined` early-return in `tick()`).
    var suppressUntil: Date?
    /// Latest known authorization status (for the menu-bar health hint).
    private(set) var authorizationDenied = false

    /// Called when we can't post via the OS (auth denied / not yet
    /// granted) so the operator still sees the alert in-app. Wired to
    /// AppDelegate.showAlertPopover.
    var onFallback: ((Alert) -> Void)?

    /// Invoked when the user TAPS a posted banner. The AppDelegate wires
    /// this to bring the dashboard window forward (LSUIElement menubar app
    /// — it may be closed) and then navigate to the alert via the
    /// `maccrab.openAlert` bridge. Mirrors the in-app popover's
    /// "Show dashboard" action. See `userNotificationCenter(_:didReceive:)`.
    var onOpenAlert: ((String) -> Void)?

    private static let cursorDefaultsKey = "maccrab.alertNotifier.cursor"

    init(dataDir: String? = AlertNotifier.resolveDataDir()) {
        self.dataDir = dataDir
        if let t = UserDefaults.standard.object(forKey: Self.cursorDefaultsKey) as? Double {
            self.cursor = Date(timeIntervalSince1970: t)
        }
        super.init()
        center.delegate = self
    }

    // MARK: - Authorization

    /// Request notification authorization once. Calling repeatedly is
    /// safe — the system only prompts while status is .notDetermined.
    func requestAuthorization() async {
        let granted = (try? await center.requestAuthorization(options: [.alert, .sound])) ?? false
        let status = await center.notificationSettings().authorizationStatus
        authorizationDenied = (status == .denied)
        logger.info("Notification authorization: granted=\(granted) status=\(status.rawValue)")
    }

    // MARK: - Poll tick (driven by the process-lifetime AppDelegate timer)

    /// Pure handoff-gate decision, extracted for unit testing. True while
    /// `suppressUntil` is a future instant. It's an ABSOLUTE deadline, so it
    /// lapses (fail-open) once `now` passes it; nil means not gated.
    // MARK: - Self-report (v1.21.6-rc.45)
    //
    // Every early return in `tick()` used to be a bare `return`. That made a
    // dead notification channel indistinguishable from a quiet one: on an
    // installed host the cursor sat frozen for six days while 2,091 alerts
    // accrued — 380 at or above the configured floor — and not one counter,
    // log line or health field said so. For the only user-facing alert surface
    // in the product, silence must be a reported state, not an absence.

    /// Why a tick ended. Recorded on every path, including the happy one.
    enum TickOutcome: String, Sendable {
        case handoffGated        = "handoff_gated"
        case storeUnavailable    = "store_unavailable"
        case fetchFailed         = "fetch_failed"
        case cursorSeeded        = "cursor_seeded"
        case nothingFresh        = "nothing_fresh"
        case authorizationPending = "authorization_pending"
        case delivered           = "delivered"
    }

    struct NotifierStatus: Sendable, Equatable {
        var ticksTotal: UInt64 = 0
        var deliveredTotal: UInt64 = 0
        var droppedByGateTotal: UInt64 = 0
        var fallbackTotal: UInt64 = 0
        /// Alerts past the cursor that this tick did not get to. Non-zero here
        /// with a stalled cursor is the exact shape of the six-day outage.
        var pendingBacklog: Int = 0
        var lastOutcome: String = "never_ticked"
        var lastTickAt: Date?
        var lastDeliveryAt: Date?
        var authorizationDenied: Bool = false
    }

    private(set) var status = NotifierStatus()

    /// Record the tick's outcome and say so out loud when the channel is silent
    /// while work exists. `.notice`, not `.debug` — this is the line that would
    /// have caught the outage.
    private func finish(_ outcome: TickOutcome, backlog: Int = 0) {
        status.ticksTotal &+= 1
        status.pendingBacklog = backlog
        status.lastOutcome = outcome.rawValue
        status.lastTickAt = Date()
        status.authorizationDenied = authorizationDenied
        switch outcome {
        case .delivered, .cursorSeeded, .nothingFresh:
            break
        case .handoffGated, .storeUnavailable, .fetchFailed, .authorizationPending:
            logger.notice(
                "alert notifier silent: \(outcome.rawValue, privacy: .public), backlog=\(backlog, privacy: .public), cursor=\(self.cursor?.description ?? "nil", privacy: .public)"
            )
        }
    }

    nonisolated static func isHandoffGated(suppressUntil: Date?, now: Date) -> Bool {
        guard let until = suppressUntil else { return false }
        return now < until
    }

    /// Read alerts newer than the cursor, gate each, and post. Cheap
    /// enough to run on the 5s status-bar timer.
    func tick() async {
        // Upgrade-handoff gate (fail-open, absolute deadline). See
        // `suppressUntil`. Return without advancing the cursor so any
        // alert that fired during the window is re-evaluated once it lifts.
        if Self.isHandoffGated(suppressUntil: suppressUntil, now: Date()) {
            finish(.handoffGated)
            return
        }
        reloadConfig()
        guard let store = openStoreIfNeeded() else {
            finish(.storeUnavailable)
            return
        }

        let since = cursor ?? Date.distantPast
        // `AlertStore.alerts(since:limit:)` is `ORDER BY timestamp DESC LIMIT n`
        // — it returns the NEWEST n. With a fixed limit of 200 and a cursor that
        // then advances to the newest alert seen, any burst larger than 200
        // between ticks silently skipped the OLDEST alerts of the burst: the
        // window returned rows 1..200 counting back from newest, the cursor
        // jumped past everything older, and those alerts were never notified.
        // That is precisely an alert storm — the moment the operator most needs
        // the channel — and it discards the earliest, usually most causally
        // interesting, alerts of the burst. Widen the window until it is no
        // longer saturated so the cursor can never step over a gap. Bounded so a
        // pathological storm cannot pull an unbounded result set into the GUI.
        var fetchLimit = 200
        var raw: [Alert]
        guard let first = try? await store.alerts(since: since, limit: fetchLimit) else {
            finish(.fetchFailed)
            return
        }
        raw = first
        while raw.count == fetchLimit && fetchLimit < 5_000 {
            fetchLimit = min(fetchLimit * 4, 5_000)
            guard let wider = try? await store.alerts(since: since, limit: fetchLimit) else { break }
            raw = wider
        }
        // Strictly newer than the cursor + not suppressed, oldest first.
        let fresh = raw
            .filter { !$0.suppressed && (cursor == nil || $0.timestamp > cursor!) }
            .sorted { $0.timestamp < $1.timestamp }

        // First run (no persisted cursor): seed to the newest alert and
        // do NOT notify the backlog.
        if cursor == nil {
            cursor = raw.map(\.timestamp).max() ?? Date()
            persistCursor()
            finish(.cursorSeeded)
            return
        }
        guard !fresh.isEmpty else {
            finish(.nothingFresh)
            return
        }

        let status = await center.notificationSettings().authorizationStatus
        authorizationDenied = (status == .denied)

        // Auth still pending (prompt not yet answered): DON'T consume these
        // alerts. Returning without advancing the cursor means they re-process
        // on a later tick once the user grants — otherwise alerts that fire in
        // the few seconds before the prompt is answered are silently lost.
        // (Denied is treated as determined: we process + fall back to the
        // in-app popover so a user who said "no" isn't stuck retrying forever.)
        if status == .notDetermined {
            finish(.authorizationPending, backlog: fresh.count)
            return
        }

        // Drain a BOUNDED slice, oldest first, and always persist what we got
        // through.
        //
        // This is hardening, not the outage fix — be precise about which. The
        // six-day silence was caused by the channel never being CONSTRUCTED
        // (see MacCrabApp.startNotificationChannel); the unbounded loop here
        // did advance the cursor when it ran. What it also did was post one
        // banner per fresh alert in a single MainActor turn: recovering from a
        // 2,091-alert backlog would have fired 2,091 banners at once. A cap of
        // 50 per 5s tick drains 600/min, bounds the burst a storm can produce,
        // and bounds the MainActor time one tick can hold.
        let slice = fresh.prefix(Self.maximumDeliveriesPerTick)
        for alert in slice {
            switch gate.evaluate(alert: alert) {
            case .deliver(let title, let body, let sound),
                 .stormSummary(let title, let body, let sound):
                post(title: title, body: body, sound: sound, alert: alert, status: status)
                self.status.deliveredTotal &+= 1
                self.status.lastDeliveryAt = Date()
            case .drop:
                self.status.droppedByGateTotal &+= 1
            }
            cursor = max(cursor ?? alert.timestamp, alert.timestamp)
        }
        persistCursor()
        let remaining = fresh.count - slice.count
        if remaining > 0 {
            logger.notice(
                "alert notifier draining backlog: delivered slice of \(slice.count, privacy: .public), \(remaining, privacy: .public) still pending"
            )
        }
        finish(.delivered, backlog: remaining)
    }

    /// Per-tick delivery cap. Bounds both the banner burst a storm can produce
    /// and the MainActor time one tick can consume.
    static let maximumDeliveriesPerTick = 50

    // MARK: - Delivery

    private func post(title: String, body: String, sound: String, alert: Alert, status: UNAuthorizationStatus) {
        // Not authorized → don't silently no-op; show the in-app popover.
        guard status == .authorized || status == .provisional else {
            self.status.fallbackTotal &+= 1
            onFallback?(alert)
            return
        }
        let content = UNMutableNotificationContent()
        content.title = title
        content.body = body
        content.sound = .default
        content.userInfo = ["alertId": alert.id]
        let request = UNNotificationRequest(
            identifier: alert.id, content: content, trigger: nil)
        center.add(request) { [weak self] error in
            if let error { self?.logger.error("post failed: \(error.localizedDescription)") }
        }
    }

    // MARK: - Config (alert_notifications.json → gate)

    /// Mirror the daemon's decode (DaemonSetup.loadAlertNotificationConfig):
    /// {enabled: Bool=true, min_severity: String=critical}. Crucially,
    /// probe BOTH the system path (/Library, where alerts.db lives) and
    /// the user-home path (~/Library, where SettingsView writes because
    /// the app can't write the root-owned /Library copy) and pick the
    /// most-recently-modified — otherwise a min_severity change made in
    /// Settings (user path) never reaches the notifier.
    private func reloadConfig() {
        let fm = FileManager.default
        let systemPath = "/Library/Application Support/MacCrab/alert_notifications.json"
        let userPath = (fm.urls(for: .applicationSupportDirectory, in: .userDomainMask)
            .first?.appendingPathComponent("MacCrab/alert_notifications.json").path)
            ?? (NSHomeDirectory() + "/Library/Application Support/MacCrab/alert_notifications.json")

        func parse(_ path: String) -> (enabled: Bool, sev: MacCrabCore.Severity, mtime: Date)? {
            guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)),
                  let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
            else { return nil }
            let enabled = json["enabled"] as? Bool ?? true
            let raw = (json["min_severity"] as? String ?? "critical").lowercased()
            let sev: MacCrabCore.Severity
            switch raw {
            case "high":          sev = .high
            case "medium":        sev = .medium
            case "low":           sev = .low
            case "informational": sev = .informational
            default:              sev = .critical
            }
            let mtime = (try? fm.attributesOfItem(atPath: path))?[.modificationDate] as? Date ?? .distantPast
            return (enabled, sev, mtime)
        }

        let sys = parse(systemPath)
        let usr = parse(userPath)
        let chosen: (enabled: Bool, sev: MacCrabCore.Severity)?
        switch (sys, usr) {
        case (nil, nil):           chosen = nil
        case (let s?, nil):        chosen = (s.enabled, s.sev)
        case (nil, let u?):        chosen = (u.enabled, u.sev)
        case (let s?, let u?):     chosen = u.mtime > s.mtime ? (u.enabled, u.sev) : (s.enabled, s.sev)
        }
        if let chosen {
            gate.enabled = chosen.enabled
            gate.minimumSeverity = chosen.sev
        }
    }

    // MARK: - Store + cursor persistence

    private var storeEpoch: EngineTelemetryIdentity?

    private func openStoreIfNeeded() -> AlertStore? {
        let epoch = V2EngineSource.session.heartbeat()?.engineIdentity
        if let previous = storeEpoch, let epoch, previous != epoch { store = nil }
        if let epoch { storeEpoch = epoch }
        if let store { return store }
        guard let dataDir else { return nil }
        store = try? AlertStore(directory: dataDir, forceReadOnly: true)
        return store
    }

    private func persistCursor() {
        if let cursor {
            UserDefaults.standard.set(cursor.timeIntervalSince1970, forKey: Self.cursorDefaultsKey)
        }
    }

    /// Match the dashboard session, including during startup before alerts.db
    /// appears. Never fall back to another engine's retained notifications.
    nonisolated private static func resolveDataDir() -> String? {
        V2EngineSource.session.directory
    }
}

// MARK: - UNUserNotificationCenterDelegate

extension AlertNotifier: UNUserNotificationCenterDelegate {
    /// Show the banner even when the dashboard window is frontmost.
    nonisolated func userNotificationCenter(
        _ center: UNUserNotificationCenter,
        willPresent notification: UNNotification
    ) async -> UNNotificationPresentationOptions {
        [.banner, .sound]
    }

    /// Tapping a banner brings the dashboard forward and opens that
    /// alert. Routes through `onOpenAlert` (wired by the AppDelegate to
    /// `showDashboard()` + the `maccrab.openAlert` bridge) — the same
    /// path the in-app alert popover uses.
    ///
    /// Pre-fix this built a `maccrab://alert/<id>` URL and posted it to
    /// `maccrab.openURL`. That URL never parsed: host "alert" ≠ the
    /// `V2Workspace` case "alerts", and the id sat in the path instead of
    /// `?entity=`, so `V2DeepLink.parse` returned nil and the tap showed a
    /// "Could not open link" toast instead of opening the alert — broken
    /// since app-owned notifications shipped (v1.17.1, 0e575c2).
    nonisolated func userNotificationCenter(
        _ center: UNUserNotificationCenter,
        didReceive response: UNNotificationResponse
    ) async {
        let alertId = response.notification.request.content.userInfo["alertId"] as? String
        await MainActor.run {
            NSApp.activate(ignoringOtherApps: true)
            if let alertId { onOpenAlert?(alertId) }
        }
    }
}
