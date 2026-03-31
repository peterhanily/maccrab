// SettingsView.swift
// HawkEyeApp
//
// Application settings view accessible via Cmd+, or the status bar menu.
// Uses @AppStorage for persistent preferences in UserDefaults.

import SwiftUI

// MARK: - SettingsView

struct SettingsView: View {
    @ObservedObject var appState: AppState
    @AppStorage("retentionDays") var retentionDays: Int = 30
    @AppStorage("alertNotifications") var alertNotifications: Bool = true
    @AppStorage("minAlertSeverity") var minAlertSeverity: String = "medium"
    @AppStorage("pollIntervalSeconds") var pollIntervalSeconds: Int = 5
    @AppStorage("launchAtLogin") var launchAtLogin: Bool = false

    var body: some View {
        TabView {
            generalTab
                .tabItem {
                    Label("General", systemImage: "gear")
                }

            notificationsTab
                .tabItem {
                    Label("Notifications", systemImage: "bell")
                }

            daemonTab
                .tabItem {
                    Label("Daemon", systemImage: "server.rack")
                }
        }
        .padding()
        .frame(width: 480, height: 320)
    }

    // MARK: General

    private var generalTab: some View {
        Form {
            Section("Data Retention") {
                Stepper(
                    "Event retention: \(retentionDays) day\(retentionDays == 1 ? "" : "s")",
                    value: $retentionDays,
                    in: 1...365,
                    step: 1
                )
                Text("Events and alerts older than this will be pruned from the database.")
                    .font(.caption)
                    .foregroundColor(.secondary)
            }

            Section("Polling") {
                Stepper(
                    "Refresh interval: \(pollIntervalSeconds) second\(pollIntervalSeconds == 1 ? "" : "s")",
                    value: $pollIntervalSeconds,
                    in: 1...60,
                    step: 1
                )
            }

            Section("Startup") {
                Toggle("Launch HawkEye at login", isOn: $launchAtLogin)
            }
        }
    }

    // MARK: Notifications

    private var notificationsTab: some View {
        Form {
            Section("Alert Notifications") {
                Toggle("Show macOS notifications for alerts", isOn: $alertNotifications)

                Picker("Minimum severity for notifications", selection: $minAlertSeverity) {
                    Text("Informational").tag("informational")
                    Text("Low").tag("low")
                    Text("Medium").tag("medium")
                    Text("High").tag("high")
                    Text("Critical only").tag("critical")
                }

                Text("Alerts below the selected severity will not generate notifications.")
                    .font(.caption)
                    .foregroundColor(.secondary)
            }
        }
    }

    // MARK: Daemon

    private var daemonTab: some View {
        Form {
            Section("Daemon Status") {
                LabeledContent("Status") {
                    HStack(spacing: 6) {
                        Circle()
                            .fill(appState.isConnected ? Color.green : Color.red)
                            .frame(width: 8, height: 8)
                        Text(appState.isConnected ? "Running" : "Stopped")
                            .foregroundColor(appState.isConnected ? .green : .red)
                    }
                }

                LabeledContent("Rules loaded") {
                    Text("\(appState.rulesLoaded)")
                }

                LabeledContent("Events/sec") {
                    Text("\(appState.eventsPerSecond)")
                }

                LabeledContent("Database") {
                    Text(databasePath)
                        .font(.caption)
                        .foregroundColor(.secondary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                }
            }

            Section("Actions") {
                Button("Reload Detection Rules") {
                    appState.reloadDaemonRules()
                }

                Button("Refresh Connection") {
                    Task {
                        await appState.refresh()
                    }
                }
            }
        }
    }

    // MARK: Private

    private var databasePath: String {
        let appSupport = FileManager.default.urls(
            for: .applicationSupportDirectory,
            in: .userDomainMask
        ).first!
        return appSupport
            .appendingPathComponent("HawkEye", isDirectory: true)
            .appendingPathComponent("events.db")
            .path
    }
}

// MARK: - Preview

#Preview {
    SettingsView(appState: AppState())
}
