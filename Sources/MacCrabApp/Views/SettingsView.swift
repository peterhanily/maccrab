// SettingsView.swift
// MacCrabApp
//
// Application settings view accessible via Cmd+, or the status bar menu.

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
                .tabItem { Label("General", systemImage: "gear") }

            notificationsTab
                .tabItem { Label("Notifications", systemImage: "bell") }

            daemonTab
                .tabItem { Label("Daemon", systemImage: "server.rack") }

            aboutTab
                .tabItem { Label("About", systemImage: "info.circle") }
        }
        .padding(20)
        .frame(width: 520, height: 380)
    }

    // MARK: - General

    private var generalTab: some View {
        VStack(alignment: .leading, spacing: 20) {
            GroupBox("Data Retention") {
                VStack(alignment: .leading, spacing: 8) {
                    HStack {
                        Text("Keep events for")
                        Stepper(
                            "\(retentionDays) days",
                            value: $retentionDays,
                            in: 1...365,
                            step: 1
                        )
                    }
                    Text("Events, alerts, and baseline data older than this will be automatically pruned.")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
                .padding(8)
            }

            GroupBox("UI Refresh") {
                VStack(alignment: .leading, spacing: 8) {
                    HStack {
                        Text("Poll daemon every")
                        Stepper(
                            "\(pollIntervalSeconds) seconds",
                            value: $pollIntervalSeconds,
                            in: 1...60,
                            step: 1
                        )
                    }
                    Text("How often the app checks the daemon's database for new events and alerts.")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
                .padding(8)
            }

            GroupBox("Startup") {
                Toggle("Launch MacCrab at login", isOn: $launchAtLogin)
                    .padding(8)
            }

            Spacer()
        }
    }

    // MARK: - Notifications

    private var notificationsTab: some View {
        VStack(alignment: .leading, spacing: 20) {
            GroupBox("macOS Notifications") {
                VStack(alignment: .leading, spacing: 12) {
                    Toggle("Show notifications for detection alerts", isOn: $alertNotifications)

                    if alertNotifications {
                        HStack {
                            Text("Minimum severity:")
                            Picker("", selection: $minAlertSeverity) {
                                Text("Informational").tag("informational")
                                Text("Low").tag("low")
                                Text("Medium").tag("medium")
                                Text("High").tag("high")
                                Text("Critical only").tag("critical")
                            }
                            .labelsHidden()
                            .frame(width: 160)
                        }

                        Text("Only alerts at or above this severity will trigger a macOS notification.")
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }
                }
                .padding(8)
            }

            Spacer()
        }
    }

    // MARK: - Daemon

    private var daemonTab: some View {
        VStack(alignment: .leading, spacing: 20) {
            GroupBox("Status") {
                VStack(spacing: 12) {
                    HStack {
                        Label("Daemon", systemImage: "server.rack")
                        Spacer()
                        HStack(spacing: 6) {
                            Circle()
                                .fill(appState.isConnected ? Color.green : Color.red)
                                .frame(width: 10, height: 10)
                            Text(appState.isConnected ? "Running" : "Stopped")
                                .fontWeight(.medium)
                                .foregroundColor(appState.isConnected ? .primary : .red)
                        }
                    }

                    Divider()

                    HStack {
                        Label("Rules loaded", systemImage: "shield.checkered")
                        Spacer()
                        Text("\(appState.rulesLoaded)")
                            .foregroundColor(.secondary)
                    }

                    HStack {
                        Label("Events/sec", systemImage: "waveform.path.ecg")
                        Spacer()
                        Text("\(appState.eventsPerSecond)")
                            .foregroundColor(.secondary)
                    }

                    HStack {
                        Label("Database", systemImage: "cylinder")
                        Spacer()
                        Text(databasePath)
                            .font(.caption)
                            .foregroundColor(.secondary)
                            .lineLimit(1)
                            .truncationMode(.middle)
                    }
                }
                .padding(8)
            }

            GroupBox("Actions") {
                HStack(spacing: 12) {
                    Button {
                        appState.reloadDaemonRules()
                    } label: {
                        Label("Reload Rules", systemImage: "arrow.clockwise")
                    }

                    Button {
                        Task { await appState.refresh() }
                    } label: {
                        Label("Refresh Connection", systemImage: "arrow.triangle.2.circlepath")
                    }
                }
                .padding(8)
            }

            Spacer()
        }
    }

    // MARK: - About

    private var aboutTab: some View {
        VStack(spacing: 16) {
            Spacer()

            Image(systemName: "shield.checkered")
                .font(.system(size: 48))
                .foregroundStyle(.blue, .orange)

            Text("MacCrab")
                .font(.title)
                .fontWeight(.bold)

            Text("Local-first macOS threat detection engine")
                .foregroundColor(.secondary)

            Text("v0.4.0")
                .font(.caption)
                .foregroundColor(.secondary)

            Divider()
                .frame(width: 200)

            VStack(spacing: 4) {
                Text("7 event sources  |  8 detection layers  |  227 rules")
                    .font(.caption)
                    .foregroundColor(.secondary)
                Text("Apache 2.0 (code)  |  DRL 1.1 (rules)")
                    .font(.caption)
                    .foregroundColor(.secondary)
            }

            Spacer()
        }
    }

    // MARK: - Private

    private var databasePath: String {
        let appSupport = FileManager.default.urls(
            for: .applicationSupportDirectory,
            in: .userDomainMask
        ).first!
        return appSupport
            .appendingPathComponent("MacCrab", isDirectory: true)
            .appendingPathComponent("events.db")
            .path
    }
}
