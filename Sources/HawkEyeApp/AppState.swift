// AppState.swift
// HawkEyeApp
//
// Observable state object that serves as the single source of truth for the
// HawkEye status bar application. Reads from the daemon's SQLite database
// and alerts.jsonl file. Polls periodically and exposes published properties
// consumed by SwiftUI views.

import SwiftUI
import Combine

// MARK: - AppState

/// Central observable state for the HawkEye menu bar application.
///
/// `AppState` periodically polls the daemon's data stores (SQLite + JSONL)
/// and publishes aggregate statistics and recent alerts. All mutations happen
/// on the main actor so SwiftUI views can bind directly to published properties.
@MainActor
final class AppState: ObservableObject {

    // MARK: Published properties

    /// Whether the app can reach the daemon's database.
    @Published var isConnected: Bool = false

    /// Most recent alerts, used for the status bar dropdown and dashboard.
    @Published var recentAlerts: [AlertViewModel] = []

    /// Approximate events per second observed during the last polling interval.
    @Published var eventsPerSecond: Int = 0

    /// Total number of unsuppressed alerts today.
    @Published var totalAlerts: Int = 0

    /// Number of detection rules currently loaded by the daemon.
    @Published var rulesLoaded: Int = 0

    /// Currently selected tab in the main window.
    @Published var selectedTab: Tab = .alerts

    /// All alerts (larger set for the dashboard view).
    @Published var dashboardAlerts: [AlertViewModel] = []

    /// Live event stream data.
    @Published var events: [EventViewModel] = []

    /// All loaded rules.
    @Published var rules: [RuleViewModel] = []

    /// TCC permission events.
    @Published var tccEvents: [TCCEventViewModel] = []

    // MARK: Tabs

    enum Tab: Hashable {
        case alerts
        case events
        case rules
        case tcc
    }

    // MARK: Derived properties

    /// SF Symbol name for the status bar icon. Changes based on alert state.
    ///
    /// - `exclamationmark.shield.fill`: At least one critical/high unsuppressed alert in last hour
    /// - `shield.lefthalf.filled`: Connected and monitoring, no urgent alerts
    /// - `shield.slash`: Not connected to daemon
    var statusIcon: String {
        guard isConnected else {
            return "shield.slash"
        }
        let hasUrgent = recentAlerts.contains { alert in
            !alert.suppressed && (alert.severity == .critical || alert.severity == .high)
        }
        return hasUrgent ? "exclamationmark.shield.fill" : "shield.lefthalf.filled"
    }

    // MARK: Polling

    private var pollTimer: AnyCancellable?
    private var previousEventCount: Int = 0

    /// Database path — shared system location readable by both daemon and app.
    private let databasePath: String = "/Library/Application Support/HawkEye/events.db"

    // MARK: Initialization

    init() {
        // Seed with mock data for development. In production, the initial
        // refresh() call below will overwrite with real data.
        loadMockData()

        // Start periodic polling every 5 seconds.
        pollTimer = Timer.publish(every: 5.0, on: .main, in: .common)
            .autoconnect()
            .sink { [weak self] _ in
                guard let self else { return }
                Task { @MainActor in
                    await self.refresh()
                }
            }

        // Perform an initial refresh.
        Task {
            await refresh()
        }
    }

    // MARK: Public interface

    /// Refresh all data from the daemon's data stores.
    func refresh() async {
        // Check daemon connectivity: is hawkeyed process running?
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/pgrep")
        task.arguments = ["-x", "hawkeyed"]
        task.standardOutput = FileHandle.nullDevice
        task.standardError = FileHandle.nullDevice
        try? task.run()
        task.waitUntilExit()
        let daemonRunning = task.terminationStatus == 0

        // Also check if DB file exists (daemon may have run previously)
        let dbExists = FileManager.default.fileExists(atPath: databasePath)
        isConnected = daemonRunning || dbExists

        guard isConnected else { return }

        // In production these would make real SQLite queries via a reader
        // connection. For now, we keep the mock data populated during init.
        // The structure is ready for integration:
        //
        // await loadAlerts(limit: 500)
        // await loadEvents(limit: 1000, filter: nil)
        // await loadRules()
        // await loadTCCEvents()
    }

    /// Load alerts from the database.
    ///
    /// - Parameter limit: Maximum number of alerts to fetch.
    func loadAlerts(limit: Int = 500) async {
        // TODO: Integration point -- read from AlertStore via a read-only
        // SQLite connection. For development, mock data is used.
        dashboardAlerts = MockData.alerts
        recentAlerts = Array(MockData.alerts.prefix(5))
        totalAlerts = dashboardAlerts.filter { !$0.suppressed }.count
    }

    /// Load events from the database.
    ///
    /// - Parameters:
    ///   - limit: Maximum number of events to fetch.
    ///   - filter: Optional FTS search string.
    func loadEvents(limit: Int = 1000, filter: String? = nil) async {
        // TODO: Integration point -- read from EventStore.
        events = MockData.events
    }

    /// Load detection rules.
    func loadRules() async {
        // TODO: Integration point -- read compiled rule JSONs from the rules
        // directory or query the daemon's rule engine via XPC/socket.
        rules = MockData.rules
        rulesLoaded = rules.count
    }

    /// Load TCC permission events.
    func loadTCCEvents() async {
        // TODO: Integration point -- query events where event_category = 'tcc'.
        tccEvents = MockData.tccEvents
    }

    /// Suppress (silence) an alert by its identifier.
    ///
    /// - Parameter alertId: The unique identifier of the alert to suppress.
    func suppressAlert(_ alertId: String) async {
        // TODO: Integration point -- call AlertStore.suppress(alertId:).
        if let index = dashboardAlerts.firstIndex(where: { $0.id == alertId }) {
            dashboardAlerts[index].suppressed = true
        }
        if let index = recentAlerts.firstIndex(where: { $0.id == alertId }) {
            recentAlerts[index].suppressed = true
        }
        totalAlerts = dashboardAlerts.filter { !$0.suppressed }.count
    }

    /// Send SIGHUP to the hawkeyed daemon to trigger a rule reload.
    func reloadDaemonRules() {
        // Find the daemon PID and send SIGHUP.
        // In production this would use a proper IPC mechanism (XPC, Unix socket).
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/pkill")
        task.arguments = ["-HUP", "hawkeyed"]
        try? task.run()
    }

    // MARK: Private

    /// Populate state with mock data for development.
    private func loadMockData() {
        recentAlerts = Array(MockData.alerts.prefix(5))
        dashboardAlerts = MockData.alerts
        events = MockData.events
        rules = MockData.rules
        tccEvents = MockData.tccEvents
        totalAlerts = dashboardAlerts.filter { !$0.suppressed }.count
        rulesLoaded = rules.count
        eventsPerSecond = 42
        isConnected = true
    }
}
