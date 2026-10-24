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
    /// The last alert considered, in commit order. Persisted so a relaunch
    /// doesn't re-notify the backlog.
    private var cursor: NotificationCursor?
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

    /// The watermark, under the key of the timestamp cursor it replaces: an
    /// older cursor resumes after it, and an older app still reads it.
    private static let cursorDefaultsKey = "maccrab.alertNotifier.cursor"
    private static let rowCursorDefaultsKey = "maccrab.alertNotifier.rowCursor"

    /// The saved cursor. This build writes the watermark under the legacy key
    /// too, always equal; an older build run in between (a downgrade, then
    /// this one again) advances only that key, so a newer legacy value wins
    /// and reading resumes after it rather than replaying what it showed.
    static func restoredCursor(rowCursor data: Data?, legacy: Double?) -> NotificationCursor? {
        let saved = data.flatMap { try? JSONDecoder().decode(NotificationCursor.self, from: $0) }
        guard let legacy else { return saved }
        if let saved, legacy <= saved.watermark.timeIntervalSince1970 + 0.001 { return saved }
        return NotificationCursor(rowID: 0, alertID: nil, watermark: Date(timeIntervalSince1970: legacy))
    }

    init(dataDir: String? = AlertNotifier.resolveDataDir()) {
        self.dataDir = dataDir
        let defaults = UserDefaults.standard
        self.cursor = Self.restoredCursor(rowCursor: defaults.data(forKey: Self.rowCursorDefaultsKey),
                                          legacy: defaults.object(forKey: Self.cursorDefaultsKey) as? Double)
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
        case disabled            = "disabled"
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
        case .delivered, .cursorSeeded, .disabled, .nothingFresh:
            break
        case .handoffGated, .storeUnavailable, .fetchFailed, .authorizationPending:
            logger.notice(
                "alert notifier silent: \(outcome.rawValue, privacy: .public), backlog=\(backlog, privacy: .public), cursor=\(self.cursor.map { "\($0.rowID)@\($0.watermark)" } ?? "nil", privacy: .public)"
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

        let center = self.center
        var status = UNAuthorizationStatus.notDetermined
        let read: ForwardRead
        do {
            read = try await Self.readForward(
                store: store, cursor: cursor,
                floor: gate.minimumSeverity, enabled: gate.enabled,
                isAuthorizationDetermined: {
                    status = await center.notificationSettings().authorizationStatus
                    return status != .notDetermined
                })
        } catch {
            finish(.fetchFailed)
            return
        }
        cursor = read.cursor
        persistCursor()
        switch read.outcome {
        case .seeded:
            finish(.cursorSeeded)
            return
        case .disabled:
            finish(.disabled)
            return
        case .nothingFresh:
            finish(.nothingFresh)
            return
        case .authorizationPending:
            // Auth still pending (prompt not yet answered): these alerts were
            // not consumed, so they re-process on a later tick once the user
            // grants — otherwise alerts that fire in the few seconds before
            // the prompt is answered are silently lost. (Denied is treated as
            // determined: we process + fall back to the in-app popover so a
            // user who said "no" isn't stuck retrying forever.)
            authorizationDenied = false
            finish(.authorizationPending, backlog: read.backlog)
            return
        case .delivered:
            break
        }
        authorizationDenied = (status == .denied)

        // A BOUNDED slice, oldest commit first, whose progress is already
        // persisted.
        //
        // This is hardening, not the outage fix — be precise about which. The
        // six-day silence was caused by the channel never being CONSTRUCTED
        // (see MacCrabApp.startNotificationChannel); the unbounded loop here
        // did advance the cursor when it ran. What it also did was post one
        // banner per fresh alert in a single MainActor turn: recovering from a
        // 2,091-alert backlog would have fired 2,091 banners at once. A cap of
        // 50 per 5s tick drains 600/min, bounds the burst a storm can produce,
        // and bounds the MainActor time one tick can hold.
        for alert in read.alerts {
            switch gate.evaluate(alert: alert) {
            case .deliver(let title, let body, let sound),
                 .stormSummary(let title, let body, let sound):
                post(title: title, body: body, sound: sound, alert: alert, status: status)
                self.status.deliveredTotal &+= 1
                self.status.lastDeliveryAt = Date()
            case .drop:
                self.status.droppedByGateTotal &+= 1
            }
        }
        if read.backlog > 0 {
            logger.notice(
                "alert notifier draining backlog: delivered slice of \(read.alerts.count, privacy: .public), \(read.backlog, privacy: .public) still pending"
            )
        }
        finish(.delivered, backlog: read.backlog)
    }

    /// Where the notifier is in alerts.db.
    struct NotificationCursor: Codable, Equatable, Sendable {
        /// The last alert considered: its rowid, the order alerts were
        /// committed in, and its id. A deleted newest alert's rowid is
        /// reused, and another alerts.db reuses every rowid, so the rowid
        /// counts only while it still names this alert.
        var rowID: Int64
        var alertID: String?
        /// The newest alert timestamp considered (or when the cursor was
        /// placed): when the rowid no longer counts, reading resumes after
        /// the newest row stamped at or before it.
        var watermark: Date

        init(rowID: Int64, alertID: String?, watermark: Date) {
            self.rowID = rowID
            self.alertID = alertID
            self.watermark = watermark
        }

        init(_ row: AlertStore.AlertRowReference?, watermark: Date) {
            self.init(rowID: row?.rowID ?? 0, alertID: row?.id, watermark: watermark)
        }
    }

    /// One tick's read: the slice to gate and post, and the cursor after it.
    struct ForwardRead {
        enum Outcome: Equatable {
            case seeded, disabled, nothingFresh, authorizationPending, delivered
        }
        var outcome: Outcome
        var alerts: [Alert] = []
        var cursor: NotificationCursor
        /// Alerts at or above the floor still waiting after this read.
        var backlog: Int = 0
    }

    /// Read forward from `cursor` in commit order, at or above `floor`, and
    /// say where the cursor goes. Authorization is asked only when there is
    /// something to deliver; until it is determined nothing is consumed.
    static func readForward(
        store: AlertStore,
        cursor saved: NotificationCursor?,
        floor: MacCrabCore.Severity,
        enabled: Bool,
        now: Date = Date(),
        isAuthorizationDetermined: () async -> Bool
    ) async throws -> ForwardRead {
        // The watermark is the newest stamp the cursor has passed, so the
        // rewrite read below finds only rows stamped again after that. It is
        // capped at the newest stamp when this read began: a row stamped again
        // after this tick's rewrite read stays above it, for the next tick.
        var ceiling = Date.distantFuture
        func passed(_ row: AlertStore.AlertRowReference?, _ watermark: Date) async throws -> Date {
            guard let row, let newest = try await store.newestTimestamp(throughRowID: row.rowID) else { return watermark }
            return max(watermark, min(newest, ceiling))
        }
        // First run: start at the newest alert and notify none of the backlog.
        // An empty table has none, so every alert after it is new.
        guard var cursor = saved else {
            let newest = try await store.newestAlertRow()
            return ForwardRead(outcome: .seeded,
                               cursor: NotificationCursor(newest, watermark: newest == nil ? .distantPast : try await passed(newest, now)))
        }
        ceiling = try await store.newestTimestamp(throughRowID: .max) ?? .distantPast
        let named = cursor.alertID == nil ? nil : try await store.alertID(atRowID: cursor.rowID)
        if named == nil || named != cursor.alertID {
            // Resume after the watermark on a row that still exists, so later
            // ticks follow its rowid instead of resolving the watermark again.
            cursor = NotificationCursor(try await store.notificationResumeRow(after: cursor.watermark),
                                        watermark: cursor.watermark)
        }
        let severities = MacCrabCore.Severity.allCases.filter { $0 >= floor }
        // A deterministic id is rewritten on its own row, behind the cursor,
        // with a new stamp and severity (a CVE re-scored as critical). Rare,
        // so all of them go in this tick, ahead of newer commits.
        let rewritten = try await store.alertsRewrittenForNotification(
            throughRowID: cursor.rowID, after: cursor.watermark, severities: severities, limit: 1_000)
        guard let newest = try await store.newestAlertRow(), newest.rowID > cursor.rowID || !rewritten.isEmpty else {
            // Nothing to read, but alerts behind the cursor may have been stamped
            // again below the floor or while suppressed: pass those stamps, so a
            // later resume by watermark does not start behind them.
            let anchor = cursor.alertID.map { AlertStore.AlertRowReference(rowID: cursor.rowID, id: $0) }
            cursor.watermark = try await passed(anchor, cursor.watermark)
            return ForwardRead(outcome: .nothingFresh, cursor: cursor)
        }
        guard enabled else {
            // Muted: everything so far counts as considered, so unmuting does
            // not replay the muted period.
            return ForwardRead(outcome: .disabled,
                               cursor: NotificationCursor(newest, watermark: try await passed(newest, max(cursor.watermark, now))))
        }
        // This tick's slice plus one row to learn whether more wait, at or
        // above the floor only: a flood below it must not hold a critical
        // banner back, a slice at a time, behind its own backlog.
        let fresh = newest.rowID > cursor.rowID
            ? try await store.alertsForNotification(
                afterRowID: cursor.rowID, throughRowID: newest.rowID,
                severities: severities, limit: Self.maximumDeliveriesPerTick + 1)
            : []
        guard !fresh.isEmpty || !rewritten.isEmpty else {
            return ForwardRead(outcome: .nothingFresh,
                               cursor: NotificationCursor(newest, watermark: try await passed(newest, cursor.watermark)))
        }
        guard await isAuthorizationDetermined() else {
            let backlog = try await store.notificationBacklogCount(afterRowID: cursor.rowID, severities: severities)
            return ForwardRead(outcome: .authorizationPending, cursor: cursor, backlog: backlog + rewritten.count)
        }
        let slice = Array(fresh.prefix(Self.maximumDeliveriesPerTick))
        let alerts = rewritten.map(\.alert) + slice.map(\.alert)
        let watermark = max(cursor.watermark, alerts.map(\.timestamp).max() ?? cursor.watermark)
        guard fresh.count > slice.count, let last = slice.last else {
            // Everything at or above the floor up to the newest row is here.
            return ForwardRead(outcome: .delivered, alerts: alerts,
                               cursor: NotificationCursor(newest, watermark: try await passed(newest, watermark)))
        }
        let reached = AlertStore.AlertRowReference(rowID: last.rowID, id: last.alert.id)
        return ForwardRead(
            outcome: .delivered, alerts: alerts,
            cursor: NotificationCursor(reached, watermark: try await passed(reached, watermark)),
            backlog: try await store.notificationBacklogCount(afterRowID: last.rowID, severities: severities)
        )
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
        guard let cursor else { return }
        UserDefaults.standard.set(cursor.watermark.timeIntervalSince1970, forKey: Self.cursorDefaultsKey)
        if let data = try? JSONEncoder().encode(cursor) {
            UserDefaults.standard.set(data, forKey: Self.rowCursorDefaultsKey)
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
