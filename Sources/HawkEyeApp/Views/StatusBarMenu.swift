// StatusBarMenu.swift
// HawkEyeApp
//
// The dropdown menu displayed when clicking the HawkEye status bar icon.
// Shows quick stats, recent alerts, and action buttons.

import SwiftUI

// MARK: - StatusBarMenu

struct StatusBarMenu: View {
    @ObservedObject var appState: AppState
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        // Connection status
        HStack(spacing: 4) {
            Image(systemName: appState.isConnected ? "circle.fill" : "circle")
                .font(.system(size: 6))
                .foregroundColor(appState.isConnected ? .green : .red)
                .accessibilityLabel(appState.isConnected ? "Daemon connected" : "Daemon disconnected")
            Text(appState.isConnected ? "HawkEye Active" : "Daemon Not Running")
                .font(.headline)
        }

        Divider()

        // Quick stats
        Label("\(appState.eventsPerSecond) events/sec", systemImage: "waveform.path.ecg")
        Label("\(appState.rulesLoaded) rules loaded", systemImage: "shield.checkered")
        Label("\(appState.totalAlerts) alerts today", systemImage: "exclamationmark.triangle")

        Divider()

        // Recent alerts (last 5)
        if appState.recentAlerts.isEmpty {
            Text("No recent alerts")
                .foregroundColor(.secondary)
        } else {
            Text("Recent Alerts")
                .font(.caption)
                .foregroundColor(.secondary)

            ForEach(appState.recentAlerts.prefix(5)) { alert in
                Button {
                    // Open the dashboard and select alerts tab
                    appState.selectedTab = .alerts
                    openWindow(id: "dashboard")
                } label: {
                    HStack(spacing: 8) {
                        Circle()
                            .fill(alert.severityColor)
                            .frame(width: 8, height: 8)
                        VStack(alignment: .leading, spacing: 1) {
                            Text(alert.ruleTitle)
                                .font(.system(.body))
                                .lineLimit(1)
                            Text("\(alert.processName) -- \(alert.timeString)")
                                .font(.system(.caption))
                                .foregroundColor(.secondary)
                        }
                    }
                }
                .accessibilityLabel("Alert: \(alert.ruleTitle), severity \(alert.severity)")
            }
        }

        Divider()

        // Actions
        Button("Open Dashboard...") {
            openWindow(id: "dashboard")
        }
        .keyboardShortcut("d")

        Button("Reload Rules") {
            appState.reloadDaemonRules()
        }
        .keyboardShortcut("r")

        Button("Refresh") {
            Task { await appState.refresh() }
        }
        .keyboardShortcut("f")

        Divider()

        if #available(macOS 14.0, *) {
            SettingsLink {
                Text("Settings...")
            }
            .keyboardShortcut(",")
        }

        Button("Quit HawkEye") {
            NSApplication.shared.terminate(nil)
        }
        .keyboardShortcut("q")
    }
}
