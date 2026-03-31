// StatusBarMenu.swift
// HawkEyeApp
//
// The dropdown menu displayed when clicking the HawkEye status bar icon.
// Shows quick stats, recent alerts, and action buttons.

import SwiftUI

// MARK: - StatusBarMenu

struct StatusBarMenu: View {
    @ObservedObject var appState: AppState

    var body: some View {
        // Connection status
        HStack(spacing: 4) {
            Image(systemName: appState.isConnected ? "circle.fill" : "circle")
                .font(.system(size: 6))
                .foregroundColor(appState.isConnected ? .green : .red)
            Text(appState.isConnected ? "HawkEye Active" : "Daemon Not Running")
                .font(.headline)
        }

        Divider()

        // Quick stats section
        Text("Events/sec: \(appState.eventsPerSecond)")
        Text("Rules loaded: \(appState.rulesLoaded)")
        Text("Alerts today: \(appState.totalAlerts)")

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
                AlertMenuItem(alert: alert)
            }
        }

        Divider()

        // Actions
        Button("Open Dashboard...") {
            openMainWindow()
        }
        .keyboardShortcut("d")

        Button("Reload Rules") {
            appState.reloadDaemonRules()
        }
        .keyboardShortcut("r")

        Button("Refresh") {
            Task {
                await appState.refresh()
            }
        }
        .keyboardShortcut("f")

        Divider()

        SettingsLink {
            Text("Settings...")
        }
        .keyboardShortcut(",")

        Button("Quit HawkEye") {
            NSApplication.shared.terminate(nil)
        }
        .keyboardShortcut("q")
    }

    // MARK: Private

    /// Opens (or brings to front) the main dashboard window.
    private func openMainWindow() {
        // On macOS 13+ with WindowGroup, we can use the environment to open
        // a window. For compatibility, we activate the app which shows the
        // WindowGroup scene.
        NSApplication.shared.activate(ignoringOtherApps: true)
        if let window = NSApplication.shared.windows.first(where: {
            $0.title == "HawkEye"
        }) {
            window.makeKeyAndOrderFront(nil)
        } else {
            // If no window exists yet, activating the app will create one
            // from the WindowGroup scene.
            NSApplication.shared.activate(ignoringOtherApps: true)
        }
    }
}

// MARK: - Preview

#Preview {
    StatusBarMenu(appState: AppState())
        .frame(width: 300)
}
