// StatusBarMenu.swift
// MacCrabApp

import SwiftUI

struct StatusBarMenu: View {
    @ObservedObject var appState: AppState

    var body: some View {
        // Connection status
        HStack(spacing: 4) {
            Image(systemName: appState.isConnected ? "circle.fill" : "circle")
                .font(.system(size: 6))
                .foregroundColor(appState.isConnected ? .green : .red)
                .accessibilityHidden(true)
            Text(appState.isConnected
                ? String(localized: "statusBar.active", defaultValue: "MacCrab Active")
                : String(localized: "statusBar.notRunning", defaultValue: "Detection Engine Not Running"))
                .font(.headline)
        }

        Divider()

        Label(title: { Text("\(appState.eventsPerSecond) events/sec") }, icon: { Image(systemName: "waveform.path.ecg") })
        Label(title: { Text("\(appState.rulesLoaded) rules loaded") }, icon: { Image(systemName: "shield.checkered") })
        Label(title: { Text("\(appState.totalAlerts) alerts today") }, icon: { Image(systemName: "exclamationmark.triangle") })

        Divider()

        if appState.recentAlerts.isEmpty {
            Text(String(localized: "statusBar.noRecentAlerts", defaultValue: "No recent alerts")).foregroundColor(.secondary)
        } else {
            Text(String(localized: "statusBar.recentAlerts", defaultValue: "Recent Alerts")).font(.caption).foregroundColor(.secondary)
            ForEach(appState.recentAlerts.prefix(5)) { alert in
                Button {
                    appState.selectedTab = .alerts
                    showDashboard()
                } label: {
                    HStack(spacing: 8) {
                        Circle().fill(alert.severityColor).frame(width: 8, height: 8)
                            .accessibilityLabel(Text("\(alert.severity.rawValue) severity"))
                        VStack(alignment: .leading, spacing: 1) {
                            Text(alert.ruleTitle).font(.body).lineLimit(1)
                            Text("\(alert.processName) -- \(alert.timeString)")
                                .font(.caption).foregroundColor(.secondary)
                        }
                    }
                }
            }
        }

        Divider()

        Button(String(localized: "statusBar.openDashboard", defaultValue: "Open Dashboard...")) { showDashboard() }
            .keyboardShortcut("d")
        Button(String(localized: "statusBar.reloadRules", defaultValue: "Reload Rules")) { appState.reloadDaemonRules() }
            .keyboardShortcut("r")
        Button(String(localized: "statusBar.refresh", defaultValue: "Refresh")) { Task { await appState.refresh() } }
            .keyboardShortcut("f")

        Divider()

        if #available(macOS 14.0, *) {
            SettingsLink { Text(String(localized: "statusBar.settings", defaultValue: "Settings...")) }.keyboardShortcut(",")
        }
        Button(String(localized: "statusBar.quit", defaultValue: "Quit MacCrab")) { NSApplication.shared.terminate(nil) }
            .keyboardShortcut("q")
    }

    private func showDashboard() {
        NSApplication.shared.activate(ignoringOtherApps: true)
        // Find or create the dashboard window
        if let window = NSApplication.shared.windows.first(where: {
            $0.title.contains("MacCrab")
        }) {
            window.makeKeyAndOrderFront(nil)
        }
    }
}
