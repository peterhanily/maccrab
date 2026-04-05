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
    @AppStorage("autoQuarantine") private var autoQuarantine = false
    @AppStorage("autoKill") private var autoKill = false
    @AppStorage("autoBlock") private var autoBlock = false

    var body: some View {
        TabView {
            generalTab
                .tabItem { Label("General", systemImage: "gear") }

            notificationsTab
                .tabItem { Label("Notifications", systemImage: "bell") }

            daemonTab
                .tabItem { Label("Daemon", systemImage: "server.rack") }

            ResponseActionsView()
                .tabItem { Label("Response Actions", systemImage: "bolt.shield") }

            aboutTab
                .tabItem { Label("About", systemImage: "info.circle") }
        }
        .padding(20)
        .frame(minWidth: 480, idealWidth: 520, maxWidth: 700, minHeight: 350, idealHeight: 400, maxHeight: 600)
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
                    .accessibilityLabel("Launch MacCrab at login")
                    .padding(8)
            }

            // Auto-Response Configuration
            GroupBox("Auto-Response") {
                VStack(alignment: .leading, spacing: 12) {
                    Text("Automatically respond to critical threats")
                        .font(.callout)

                    Toggle("Auto-quarantine malicious files", isOn: $autoQuarantine)
                        .accessibilityLabel("Auto-quarantine malicious files")
                        .accessibilityHint("Applies only to critical severity alerts")
                        .help("Automatically move files flagged by critical-severity rules to quarantine")

                    Toggle("Auto-kill malicious processes", isOn: $autoKill)
                        .accessibilityLabel("Auto-kill malicious processes")
                        .accessibilityHint("Applies only to critical severity alerts")
                        .help("Automatically terminate processes that trigger critical detection rules")

                    Toggle("Auto-block C2 destinations", isOn: $autoBlock)
                        .accessibilityLabel("Auto-block C2 destinations")
                        .accessibilityHint("Applies only to critical severity alerts")
                        .help("Automatically add PF firewall rules to block command-and-control IPs")

                    Text("These actions apply only to CRITICAL severity alerts. Configure per-rule actions in Response Actions tab.")
                        .font(.caption).foregroundColor(.secondary)
                }.padding(8)
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
                        .accessibilityLabel("Show notifications for detection alerts")

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

            Text("🦀")
                .font(.system(size: 64))

            Text("MacCrab")
                .font(.title)
                .fontWeight(.bold)

            Text("Local-first macOS threat detection engine")
                .foregroundColor(.secondary)

            Text("v0.5.0")
                .font(.caption)
                .foregroundColor(.secondary)

            Divider()
                .frame(width: 200)

            VStack(spacing: 4) {
                Text("7 event sources | 8 detection layers | 241 rules")
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
        let fm = FileManager.default
        let userDir = fm.urls(
            for: .applicationSupportDirectory,
            in: .userDomainMask
        ).first.map { $0.appendingPathComponent("MacCrab").path }
            ?? NSHomeDirectory() + "/Library/Application Support/MacCrab"
        let systemDir = "/Library/Application Support/MacCrab"

        let userDB = userDir + "/events.db"
        let systemDB = systemDir + "/events.db"
        let userExists = fm.fileExists(atPath: userDB)
        let systemReadable = fm.isReadableFile(atPath: systemDB)

        if userExists && systemReadable {
            let userMod = (try? fm.attributesOfItem(atPath: userDB))?[.modificationDate] as? Date
            let sysMod = (try? fm.attributesOfItem(atPath: systemDB))?[.modificationDate] as? Date
            if let s = sysMod, let u = userMod, s >= u {
                return systemDB
            }
            return userDB
        }
        if systemReadable { return systemDB }
        if userExists { return userDB }
        return systemDB
    }
}
