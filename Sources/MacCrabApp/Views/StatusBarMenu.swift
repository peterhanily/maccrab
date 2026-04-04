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
            Text(appState.isConnected ? "MacCrab Active" : "Daemon Not Running")
                .font(.headline)
        }

        Divider()

        Label("\(appState.eventsPerSecond) events/sec", systemImage: "waveform.path.ecg")
        Label("\(appState.rulesLoaded) rules loaded", systemImage: "shield.checkered")
        Label("\(appState.totalAlerts) alerts today", systemImage: "exclamationmark.triangle")

        Divider()

        if appState.recentAlerts.isEmpty {
            Text("No recent alerts").foregroundColor(.secondary)
        } else {
            Text("Recent Alerts").font(.caption).foregroundColor(.secondary)
            ForEach(appState.recentAlerts.prefix(5)) { alert in
                Button {
                    appState.selectedTab = .alerts
                    showDashboard()
                } label: {
                    HStack(spacing: 8) {
                        Circle().fill(alert.severityColor).frame(width: 8, height: 8)
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

        Button("Open Dashboard...") { showDashboard() }
            .keyboardShortcut("d")
        Button("Reload Rules") { appState.reloadDaemonRules() }
            .keyboardShortcut("r")
        Button("Refresh") { Task { await appState.refresh() } }
            .keyboardShortcut("f")

        Divider()

        if #available(macOS 14.0, *) {
            SettingsLink { Text("Settings...") }.keyboardShortcut(",")
        }
        Button("Quit MacCrab") { NSApplication.shared.terminate(nil) }
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
