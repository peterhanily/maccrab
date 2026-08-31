// AlertNotifierLifetimeTests.swift
//
// v1.21.6-rc.45: the OS-banner channel must outlive any window.
//
// THE OUTAGE THIS PINS (measured on an installed host, 2026-08-31):
// the persisted notifier cursor sat frozen at 2026-08-25 23:13:43 for six
// days. In that window `alerts.db` gained 2,091 unsuppressed alerts, 380 of
// them at or above the configured `min_severity: high` floor. Zero banners
// were posted, and nothing — no counter, no log line, no health field —
// reported it. OS banners are the ONLY user-facing alert surface: the
// daemon's `NotificationOutput.notify` has been a logger-only no-op since
// v1.17.
//
// ROOT CAUSE: `AlertNotifier` and its 5s timer were constructed inside
// `AppDelegate.setupStatusBar`, whose sole call site was a SwiftUI
// `.onAppear` (MacCrabApp.swift:89). MacCrab is `LSUIElement = true`, so a
// launch that never opens the dashboard window never built the notifier and
// never armed the timer. `createStatusBarItem()` had already been moved to
// `applicationDidFinishLaunching` in v1.4.3 for exactly this reason; the
// alert channel was left behind.
//
// These are source-structure assertions, matching the convention in
// HeavyEnrichmentPlaneTests.sourceOwnershipGuard. A behavioural test cannot
// reach this: it is about which lifecycle hook owns the object, and building
// a real AppDelegate in a test would arm a status item and a live timer.

import Testing
import Foundation

@Suite("Alert notifier lifetime (v1.21.6-rc.45)")
struct AlertNotifierLifetimeTests {

    private func source(_ relative: String) throws -> String {
        let root = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
        return try String(
            contentsOf: root.appendingPathComponent(relative), encoding: .utf8
        )
    }

    @Test("the notification channel is started from applicationDidFinishLaunching")
    func channelStartsAtLaunch() throws {
        let app = try source("Sources/MacCrabApp/MacCrabApp.swift")

        #expect(
            app.contains("@MainActor func startNotificationChannel()"),
            "the channel must be owned by a named, idempotent function, not inlined in view setup"
        )

        // The launch hook must start it. Slice from the launch hook to the next
        // function so a call somewhere else in the file cannot satisfy this.
        guard let launchStart = app.range(
            of: "func applicationDidFinishLaunching(_ notification: Notification) {"
        ) else {
            Issue.record("applicationDidFinishLaunching not found")
            return
        }
        let afterLaunch = String(app[launchStart.upperBound...].prefix(4_000))
        #expect(
            afterLaunch.contains("startNotificationChannel()"),
            "applicationDidFinishLaunching must start the notification channel; without it a windowless LSUIElement launch posts no banners at all"
        )
    }

    @Test("setupStatusBar no longer owns the notifier or its timer")
    func viewSetupDoesNotOwnTheChannel() throws {
        let app = try source("Sources/MacCrabApp/MacCrabApp.swift")
        guard let setupStart = app.range(
            of: "@MainActor func setupStatusBar(appState: AppState"
        ) else {
            Issue.record("setupStatusBar not found")
            return
        }
        let body = String(app[setupStart.upperBound...].prefix(4_000))

        #expect(
            !body.contains("let notifier = AlertNotifier()"),
            "constructing the notifier here ties the only alert surface to a view's onAppear"
        )
        #expect(
            !body.contains("Timer.scheduledTimer(withTimeInterval: 5.0"),
            "arming the delivery timer here ties it to a view's onAppear"
        )
        // It may still CALL the idempotent starter — that keeps a window-first
        // launch order converging.
        #expect(body.contains("startNotificationChannel()"))
    }

    @Test("every tick outcome is recorded, so silence is a reported state")
    func everyTickOutcomeIsRecorded() throws {
        let notifier = try source("Sources/MacCrabApp/AlertNotifier.swift")

        for outcome in [
            "handoffGated", "storeUnavailable", "fetchFailed",
            "cursorSeeded", "nothingFresh", "authorizationPending", "delivered",
        ] {
            #expect(
                notifier.contains("finish(.\(outcome)"),
                "tick() must record the \(outcome) exit rather than returning bare"
            )
        }

        // The six-day outage was invisible because every early return was a
        // bare `return`. Guard the shape that made it invisible.
        #expect(
            notifier.contains("logger.notice("),
            "a silent channel with work pending must log at .notice, not .debug"
        )
        #expect(
            notifier.contains("var pendingBacklog: Int"),
            "the status must expose how much work the channel is not doing"
        )
    }

    @Test("the drain is bounded so one tick cannot fire a whole backlog")
    func drainIsBounded() throws {
        let notifier = try source("Sources/MacCrabApp/AlertNotifier.swift")
        #expect(notifier.contains("static let maximumDeliveriesPerTick = 50"))
        #expect(
            notifier.contains("fresh.prefix(Self.maximumDeliveriesPerTick)"),
            "recovering from a 2,091-alert backlog must not post 2,091 banners in one MainActor turn"
        )
        #expect(
            notifier.contains("persistCursor()"),
            "the cursor must persist every tick so progress is never lost"
        )
    }
}
