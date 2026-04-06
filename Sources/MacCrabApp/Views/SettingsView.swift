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

    // Webhook notification settings
    @AppStorage("webhookSlackURL") private var webhookSlackURL: String = ""
    @AppStorage("webhookTeamsURL") private var webhookTeamsURL: String = ""
    @AppStorage("webhookDiscordURL") private var webhookDiscordURL: String = ""
    @AppStorage("webhookPagerDutyKey") private var webhookPagerDutyKey: String = ""
    @AppStorage("webhookMinSeverity") private var webhookMinSeverity: String = "high"

    var body: some View {
        TabView {
            generalTab
                .tabItem { Label(String(localized: "settings.general", defaultValue: "General"), systemImage: "gear") }

            notificationsTab
                .tabItem { Label(String(localized: "settings.notifications", defaultValue: "Notifications"), systemImage: "bell") }

            daemonTab
                .tabItem { Label(String(localized: "settings.daemon", defaultValue: "Daemon"), systemImage: "server.rack") }

            ResponseActionsView()
                .tabItem { Label(String(localized: "settings.responseActions", defaultValue: "Response Actions"), systemImage: "bolt.shield") }

            aboutTab
                .tabItem { Label(String(localized: "settings.about", defaultValue: "About"), systemImage: "info.circle") }
        }
        .padding(20)
        .frame(minWidth: 480, idealWidth: 520, maxWidth: 700, minHeight: 350, idealHeight: 500, maxHeight: 800)
    }

    // MARK: - General

    private var generalTab: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                GroupBox(String(localized: "settings.dataRetention", defaultValue: "Data Retention")) {
                    VStack(alignment: .leading, spacing: 8) {
                        HStack {
                            Text(String(localized: "settings.keepEventsFor", defaultValue: "Keep events for"))
                            Stepper(
                                "\(retentionDays) days",
                                value: $retentionDays,
                                in: 1...365,
                                step: 1
                            )
                        }
                        Text(String(localized: "settings.retentionHelp", defaultValue: "Events, alerts, and baseline data older than this will be automatically pruned."))
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }
                    .padding(8)
                }

                GroupBox(String(localized: "settings.uiRefresh", defaultValue: "UI Refresh")) {
                    VStack(alignment: .leading, spacing: 8) {
                        HStack {
                            Text(String(localized: "settings.pollDaemon", defaultValue: "Poll daemon every"))
                            Stepper(
                                "\(pollIntervalSeconds) seconds",
                                value: $pollIntervalSeconds,
                                in: 1...60,
                                step: 1
                            )
                        }
                        Text(String(localized: "settings.pollHelp", defaultValue: "How often the app checks the daemon's database for new events and alerts."))
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }
                    .padding(8)
                }

                GroupBox(String(localized: "settings.startup", defaultValue: "Startup")) {
                    Toggle(String(localized: "settings.launchAtLogin", defaultValue: "Launch MacCrab at login"), isOn: $launchAtLogin)
                        .accessibilityLabel("Launch MacCrab at login")
                        .padding(8)
                }

                // Auto-Response Configuration
                GroupBox(String(localized: "settings.autoResponse", defaultValue: "Auto-Response")) {
                    VStack(alignment: .leading, spacing: 12) {
                        Text(String(localized: "settings.autoResponseDesc", defaultValue: "Automatically respond to critical threats"))
                            .font(.callout)

                        Toggle(String(localized: "settings.autoQuarantine", defaultValue: "Auto-quarantine malicious files"), isOn: $autoQuarantine)
                            .accessibilityLabel("Auto-quarantine malicious files")
                            .accessibilityHint("Applies only to critical severity alerts")
                            .help("Automatically move files flagged by critical-severity rules to quarantine")

                        Toggle(String(localized: "settings.autoKill", defaultValue: "Auto-kill malicious processes"), isOn: $autoKill)
                            .accessibilityLabel("Auto-kill malicious processes")
                            .accessibilityHint("Applies only to critical severity alerts")
                            .help("Automatically terminate processes that trigger critical detection rules")

                        Toggle(String(localized: "settings.autoBlock", defaultValue: "Auto-block C2 destinations"), isOn: $autoBlock)
                            .accessibilityLabel("Auto-block C2 destinations")
                            .accessibilityHint("Applies only to critical severity alerts")
                            .help("Automatically add PF firewall rules to block command-and-control IPs")

                        Text(String(localized: "settings.autoResponseNote", defaultValue: "These actions apply only to CRITICAL severity alerts. Configure per-rule actions in Response Actions tab."))
                            .font(.caption).foregroundColor(.secondary)
                    }.padding(8)
                }

                Spacer()
            }
            .padding(4)
        }
    }

    // MARK: - Notifications

    private var notificationsTab: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                GroupBox(String(localized: "settings.macosNotifications", defaultValue: "macOS Notifications")) {
                    VStack(alignment: .leading, spacing: 12) {
                        Toggle(String(localized: "settings.showNotifications", defaultValue: "Show notifications for detection alerts"), isOn: $alertNotifications)
                            .accessibilityLabel("Show notifications for detection alerts")

                        if alertNotifications {
                            HStack {
                                Text(String(localized: "settings.minimumSeverity", defaultValue: "Minimum severity:"))
                                Picker("", selection: $minAlertSeverity) {
                                    Text(String(localized: "settings.informational", defaultValue: "Informational")).tag("informational")
                                    Text(String(localized: "settings.low", defaultValue: "Low")).tag("low")
                                    Text(String(localized: "settings.medium", defaultValue: "Medium")).tag("medium")
                                    Text(String(localized: "settings.high", defaultValue: "High")).tag("high")
                                    Text(String(localized: "settings.criticalOnly", defaultValue: "Critical only")).tag("critical")
                                }
                                .labelsHidden()
                                .frame(width: 160)
                            }

                            Text(String(localized: "settings.severityHelp", defaultValue: "Only alerts at or above this severity will trigger a macOS notification."))
                                .font(.caption)
                                .foregroundColor(.secondary)
                        }
                    }
                    .padding(8)
                }

                GroupBox(String(localized: "settings.webhookIntegrations", defaultValue: "Webhook Integrations")) {
                    VStack(alignment: .leading, spacing: 12) {
                        Text(String(localized: "settings.webhookDesc", defaultValue: "Send alerts to external services. Leave blank to disable."))
                            .font(.caption)
                            .foregroundColor(.secondary)

                        HStack {
                            Text(String(localized: "settings.webhookMinSeverity", defaultValue: "Minimum severity:"))
                            Picker("", selection: $webhookMinSeverity) {
                                Text(String(localized: "settings.low", defaultValue: "Low")).tag("low")
                                Text(String(localized: "settings.medium", defaultValue: "Medium")).tag("medium")
                                Text(String(localized: "settings.high", defaultValue: "High")).tag("high")
                                Text(String(localized: "settings.criticalOnly", defaultValue: "Critical only")).tag("critical")
                            }
                            .labelsHidden()
                            .frame(width: 160)
                        }

                        Divider()

                        VStack(alignment: .leading, spacing: 4) {
                            Text(String(localized: "settings.slackWebhook", defaultValue: "Slack Webhook URL"))
                                .font(.caption).fontWeight(.medium)
                            TextField("https://hooks.slack.com/services/...", text: $webhookSlackURL)
                                .textFieldStyle(.roundedBorder)
                                .font(.caption)
                        }

                        VStack(alignment: .leading, spacing: 4) {
                            Text(String(localized: "settings.teamsWebhook", defaultValue: "Microsoft Teams Webhook URL"))
                                .font(.caption).fontWeight(.medium)
                            TextField("https://outlook.office.com/webhook/...", text: $webhookTeamsURL)
                                .textFieldStyle(.roundedBorder)
                                .font(.caption)
                        }

                        VStack(alignment: .leading, spacing: 4) {
                            Text(String(localized: "settings.discordWebhook", defaultValue: "Discord Webhook URL"))
                                .font(.caption).fontWeight(.medium)
                            TextField("https://discord.com/api/webhooks/...", text: $webhookDiscordURL)
                                .textFieldStyle(.roundedBorder)
                                .font(.caption)
                        }

                        VStack(alignment: .leading, spacing: 4) {
                            Text(String(localized: "settings.pagerdutyKey", defaultValue: "PagerDuty Routing Key"))
                                .font(.caption).fontWeight(.medium)
                            TextField("e93facc04764012d7bfb002500d5d1a6...", text: $webhookPagerDutyKey)
                                .textFieldStyle(.roundedBorder)
                                .font(.caption)
                        }

                        webhookStatusView
                    }
                    .padding(8)
                }

                Spacer()
            }
            .padding(4)
        }
    }

    // MARK: - Webhook Status

    private var webhookStatusView: some View {
        let configured = [
            (!webhookSlackURL.isEmpty, "Slack"),
            (!webhookTeamsURL.isEmpty, "Teams"),
            (!webhookDiscordURL.isEmpty, "Discord"),
            (!webhookPagerDutyKey.isEmpty, "PagerDuty"),
        ].filter(\.0).map(\.1)

        return Group {
            if configured.isEmpty {
                Text(String(localized: "settings.noWebhooksConfigured", defaultValue: "No webhook integrations configured"))
                    .font(.caption)
                    .foregroundColor(.secondary)
            } else {
                HStack(spacing: 4) {
                    Image(systemName: "checkmark.circle.fill")
                        .foregroundColor(.green)
                        .font(.caption)
                    Text(String(localized: "settings.webhooksActive", defaultValue: "Active: \(configured.joined(separator: ", "))"))
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
            }
        }
    }

    // MARK: - Daemon

    private var daemonTab: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                GroupBox(String(localized: "settings.daemonStatus", defaultValue: "Status")) {
                    VStack(spacing: 12) {
                        HStack {
                            Label(String(localized: "settings.daemon", defaultValue: "Daemon"), systemImage: "server.rack")
                            Spacer()
                            HStack(spacing: 6) {
                                Circle()
                                    .fill(appState.isConnected ? Color.green : Color.red)
                                    .frame(width: 10, height: 10)
                                Text(appState.isConnected
                                    ? String(localized: "settings.daemonRunning", defaultValue: "Running")
                                    : String(localized: "settings.daemonStopped", defaultValue: "Stopped"))
                                    .fontWeight(.medium)
                                    .foregroundColor(appState.isConnected ? .primary : .red)
                            }
                        }

                        Divider()

                        HStack {
                            Label(String(localized: "settings.rulesLoaded", defaultValue: "Rules loaded"), systemImage: "shield.checkered")
                            Spacer()
                            Text("\(appState.rulesLoaded)")
                                .foregroundColor(.secondary)
                        }

                        HStack {
                            Label(String(localized: "settings.eventsPerSec", defaultValue: "Events/sec"), systemImage: "waveform.path.ecg")
                            Spacer()
                            Text("\(appState.eventsPerSecond)")
                                .foregroundColor(.secondary)
                        }

                        HStack {
                            Label(String(localized: "settings.database", defaultValue: "Database"), systemImage: "cylinder")
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

                GroupBox(String(localized: "settings.actions", defaultValue: "Actions")) {
                    HStack(spacing: 12) {
                        Button {
                            appState.reloadDaemonRules()
                        } label: {
                            Label(String(localized: "settings.reloadRules", defaultValue: "Reload Rules"), systemImage: "arrow.clockwise")
                        }

                        Button {
                            Task { await appState.refresh() }
                        } label: {
                            Label(String(localized: "settings.refreshConnection", defaultValue: "Refresh Connection"), systemImage: "arrow.triangle.2.circlepath")
                        }
                    }
                    .padding(8)
                }

                Spacer()
            }
            .padding(4)
        }
    }

    // MARK: - About

    private var aboutTab: some View {
        ScrollView {
            VStack(spacing: 16) {
                Spacer()

                Text("🦀")
                    .font(.system(size: 64))

                Text("MacCrab")
                    .font(.title)
                    .fontWeight(.bold)

                Text(String(localized: "settings.aboutTagline", defaultValue: "Local-first macOS threat detection engine"))
                    .foregroundColor(.secondary)

                Text("v0.5.0")
                    .font(.caption)
                    .foregroundColor(.secondary)

                Divider()
                    .frame(width: 200)

                VStack(spacing: 4) {
                    Text(String(localized: "settings.aboutStats", defaultValue: "7 event sources | 8 detection layers | 241 rules"))
                        .font(.caption)
                        .foregroundColor(.secondary)
                    Text(String(localized: "settings.aboutLicense", defaultValue: "Apache 2.0 (code)  |  DRL 1.1 (rules)"))
                        .font(.caption)
                        .foregroundColor(.secondary)
                }

                Spacer()
            }
            .padding(4)
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
