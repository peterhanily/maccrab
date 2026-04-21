// SettingsView.swift
// MacCrabApp
//
// Application settings view accessible via Cmd+, or the status bar menu.

import SwiftUI
import MacCrabCore
import ServiceManagement
import Sparkle
import os.log

// MARK: - SettingsView

struct SettingsView: View {
    @ObservedObject var appState: AppState
    @AppStorage("retentionDays") var retentionDays: Int = 30
    @AppStorage("alertNotifications") var alertNotifications: Bool = true
    @AppStorage("minAlertSeverity") var minAlertSeverity: String = "medium"
    @AppStorage("pollIntervalSeconds") var pollIntervalSeconds: Int = 5
    // Launch at login is backed by macOS's ServiceManagement framework —
    // the @AppStorage value mirrors the registration state, so we can
    // present a SwiftUI-native Toggle while the actual login-item
    // registration is done via SMAppService. Default `true` — new and
    // upgrading installs get auto-start. Users who don't want it can
    // untoggle; that removes the login item and we keep the preference.
    @AppStorage("launchAtLogin") var launchAtLogin: Bool = true
    @AppStorage("autoQuarantine") private var autoQuarantine = false
    @AppStorage("autoKill") private var autoKill = false
    @AppStorage("autoBlock") private var autoBlock = false
    @AppStorage("maxDatabaseSizeMB") private var maxDatabaseSizeMB: Int = 500
    @AppStorage("retentionWindowDays") private var retentionWindowDays: Int = 30
    @State private var retentionConfirmShown: Bool = false

    // LLM settings (provider selection + URLs persist to UserDefaults; API
    // keys live in the Keychain via SecretsStore — see `llmAPIKey` below).
    @AppStorage("llm.provider") private var llmProvider: String = "ollama"
    @AppStorage("llm.ollamaURL") private var llmOllamaURL: String = "http://localhost:11434"
    @AppStorage("llm.ollamaModel") private var llmOllamaModel: String = "llama3.1:8b"
    @AppStorage("llm.openaiURL") private var llmOpenAIURL: String = "https://api.openai.com/v1"
    @AppStorage("llm.model") private var llmModel: String = ""
    @AppStorage("llm.enabled") private var llmEnabled: Bool = false

    // API key is @State, not @AppStorage — the previous @AppStorage backing
    // wrote secrets to `~/Library/Preferences/com.maccrab.app.plist` (default
    // 0644, world-readable). Now the authoritative store is the Keychain
    // (SecretsStore), keyed per-provider. The SecureField binds to this
    // transient state; `syncLLMConfig()` persists it, `loadAPIKeyForProvider()`
    // populates it on appear / provider change.
    @State private var llmAPIKey: String = ""
    private let secrets = SecretsStore()

    @State private var selectedLanguage: String = {
        let current = UserDefaults.standard.stringArray(forKey: "AppleLanguages")?.first ?? "en"
        return current
    }()
    @State private var initialLanguage: String = {
        UserDefaults.standard.stringArray(forKey: "AppleLanguages")?.first ?? "en"
    }()

    private var languageChanged: Bool { selectedLanguage != initialLanguage }

    private let availableLanguages: [(code: String, name: String, native: String)] = [
        ("en", "English", "English"),
        ("es", "Spanish", "Español"),
        ("fr", "French", "Français"),
        ("de", "German", "Deutsch"),
        ("ja", "Japanese", "日本語"),
        ("zh-Hans", "Chinese (Simplified)", "简体中文"),
        ("ko", "Korean", "한국어"),
        ("pt-BR", "Portuguese (Brazil)", "Português"),
        ("it", "Italian", "Italiano"),
        ("nl", "Dutch", "Nederlands"),
        ("zh-Hant", "Chinese (Traditional)", "繁體中文"),
        ("ru", "Russian", "Русский"),
        ("sv", "Swedish", "Svenska"),
        ("pl", "Polish", "Polski"),
    ]

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

            appearanceTab
                .tabItem { Label(String(localized: "settings.appearance", defaultValue: "Appearance"), systemImage: "eye") }

            notificationsTab
                .tabItem { Label(String(localized: "settings.notifications", defaultValue: "Notifications"), systemImage: "bell") }

            daemonTab
                .tabItem { Label(String(localized: "settings.daemon", defaultValue: "Detection Engine"), systemImage: "server.rack") }

            ResponseActionsView()
                .tabItem { Label(String(localized: "settings.responseActions", defaultValue: "Response Actions"), systemImage: "bolt.shield") }

            llmTab
                .tabItem { Label(String(localized: "settings.aiBackend", defaultValue: "AI Backend"), systemImage: "brain.head.profile") }

            aboutTab
                .tabItem { Label(String(localized: "settings.about", defaultValue: "About"), systemImage: "info.circle") }
        }
        .padding(20)
        .frame(minWidth: 480, idealWidth: 520, maxWidth: 700, minHeight: 350, idealHeight: 500, maxHeight: 800)
    }

    // MARK: - Appearance

    @AppStorage(UIMode.storageKey) private var uiModeRaw: String = UIMode.advanced.rawValue

    private var uiMode: Binding<UIMode> {
        Binding(
            get: { UIMode(rawValue: self.uiModeRaw) ?? .advanced },
            set: { self.uiModeRaw = $0.rawValue }
        )
    }

    private var appearanceTab: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                Text(String(localized: "appearance.title", defaultValue: "Dashboard complexity"))
                    .font(.headline)

                Text(String(localized: "appearance.hint", defaultValue: "Hide views you don't use. Every mode keeps detection fully active — this only affects the sidebar."))
                    .font(.caption)
                    .foregroundColor(.secondary)

                Picker(
                    String(localized: "appearance.mode", defaultValue: "Mode"),
                    selection: uiMode
                ) {
                    ForEach(UIMode.allCases, id: \.self) { mode in
                        Text(mode.displayName).tag(mode)
                    }
                }
                .pickerStyle(.segmented)

                VStack(alignment: .leading, spacing: 8) {
                    ForEach(UIMode.allCases, id: \.self) { mode in
                        HStack(alignment: .top, spacing: 6) {
                            Image(systemName: uiMode.wrappedValue == mode ? "largecircle.fill.circle" : "circle")
                                .foregroundColor(uiMode.wrappedValue == mode ? .accentColor : .secondary)
                                .font(.caption)
                            VStack(alignment: .leading, spacing: 1) {
                                Text(mode.displayName).font(.subheadline).fontWeight(.medium)
                                Text(mode.summary).font(.caption).foregroundColor(.secondary)
                            }
                        }
                    }
                }
                .padding(.top, 4)

                Divider().padding(.vertical, 6)

                Text(String(localized: "appearance.note", defaultValue: "Tip: detection, prevention, and response are always on regardless of mode. Only the dashboard navigation changes."))
                    .font(.caption)
                    .foregroundColor(.secondary)
                    .italic()

                Spacer()
            }
            .padding(4)
        }
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

                GroupBox(String(localized: "settings.storageLimit", defaultValue: "Storage Limit")) {
                    VStack(alignment: .leading, spacing: 8) {
                        HStack {
                            Text(String(localized: "settings.maxDBSize", defaultValue: "Max database size"))
                            Stepper(
                                "\(maxDatabaseSizeMB) MB",
                                value: $maxDatabaseSizeMB,
                                in: 100...5000,
                                step: 100
                            )
                        }

                        HStack {
                            Text(String(localized: "settings.currentDBSize", defaultValue: "Current size:"))
                                .font(.caption)
                                .foregroundColor(.secondary)
                            Text(currentDatabaseSize)
                                .font(.system(.caption, design: .monospaced))
                                .foregroundColor(isDatabaseNearLimit ? .orange : .secondary)
                        }

                        Text(String(localized: "settings.storageLimitHelp", defaultValue: "When the database exceeds this size, the oldest events will be pruned automatically."))
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }
                    .padding(8)
                }

                GroupBox(String(localized: "settings.uiRefresh", defaultValue: "UI Refresh")) {
                    VStack(alignment: .leading, spacing: 8) {
                        HStack {
                            Text(String(localized: "settings.pollDaemon", defaultValue: "Poll detection engine every"))
                            Stepper(
                                "\(pollIntervalSeconds) seconds",
                                value: $pollIntervalSeconds,
                                in: 1...60,
                                step: 1
                            )
                        }
                        Text(String(localized: "settings.pollHelp", defaultValue: "How often the app checks the detection engine's database for new events and alerts."))
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }
                    .padding(8)
                }

                GroupBox(String(localized: "settings.language", defaultValue: "Language")) {
                    VStack(alignment: .leading, spacing: 8) {
                        Picker(String(localized: "settings.displayLanguage", defaultValue: "Display language"), selection: $selectedLanguage) {
                            ForEach(availableLanguages, id: \.code) { lang in
                                Text("\(lang.native) (\(lang.name))").tag(lang.code)
                            }
                        }
                        .onChange(of: selectedLanguage) { newValue in
                            UserDefaults.standard.set([newValue], forKey: "AppleLanguages")
                            UserDefaults.standard.synchronize()
                            // Also set for the specific bundle ID
                            if let bundleId = Bundle.main.bundleIdentifier {
                                UserDefaults(suiteName: bundleId)?.set([newValue], forKey: "AppleLanguages")
                                UserDefaults(suiteName: bundleId)?.synchronize()
                            }
                        }

                        if languageChanged {
                            HStack(spacing: 6) {
                                Image(systemName: "arrow.clockwise")
                                    .font(.caption)
                                    .foregroundColor(.orange)
                                    .accessibilityHidden(true)
                                Text(String(localized: "settings.restartForLanguage", defaultValue: "Restart MacCrab to apply language change"))
                                    .font(.caption)
                                    .foregroundColor(.orange)
                            }
                        }
                    }
                    .padding(8)
                }

                GroupBox(String(localized: "settings.startup", defaultValue: "Startup")) {
                    VStack(alignment: .leading, spacing: 6) {
                        Toggle(String(localized: "settings.launchAtLogin", defaultValue: "Launch MacCrab at login"), isOn: $launchAtLogin)
                            .onChange(of: launchAtLogin) { newValue in
                                LaunchAtLogin.setEnabled(newValue)
                            }
                        Text(String(
                            localized: "settings.launchAtLoginHint",
                            defaultValue: "On by default so your detection engine reactivates after every reboot. Turn off if you'd rather start MacCrab manually."
                        ))
                        .font(.caption)
                        .foregroundColor(.secondary)
                    }
                    .padding(8)
                }

                // Auto-Response Configuration
                GroupBox(String(localized: "settings.autoResponse", defaultValue: "Auto-Response")) {
                    VStack(alignment: .leading, spacing: 12) {
                        Text(String(localized: "settings.autoResponseDesc", defaultValue: "Automatically respond to critical threats"))
                            .font(.callout)

                        Toggle(String(localized: "settings.autoQuarantine", defaultValue: "Auto-quarantine malicious files"), isOn: $autoQuarantine)
                            .accessibilityHint(String(localized: "settings.access.criticalOnlyHint", defaultValue: "Applies only to critical severity alerts"))
                            .help(String(localized: "settings.help.autoQuarantine", defaultValue: "Automatically move files flagged by critical-severity rules to quarantine"))

                        Toggle(String(localized: "settings.autoKill", defaultValue: "Auto-kill malicious processes"), isOn: $autoKill)
                            .accessibilityHint(String(localized: "settings.access.criticalOnlyHint", defaultValue: "Applies only to critical severity alerts"))
                            .help(String(localized: "settings.help.autoKill", defaultValue: "Automatically terminate processes that trigger critical detection rules"))

                        Toggle(String(localized: "settings.autoBlock", defaultValue: "Auto-block C2 destinations"), isOn: $autoBlock)
                            .accessibilityHint(String(localized: "settings.access.criticalOnlyHint", defaultValue: "Applies only to critical severity alerts"))
                            .help(String(localized: "settings.help.autoBlock", defaultValue: "Automatically add PF firewall rules to block command-and-control IPs"))

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
                        .accessibilityHidden(true)
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
                            Label(String(localized: "settings.daemon", defaultValue: "Detection Engine"), systemImage: "server.rack")
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

                        // In-UI path to trigger a Sparkle update check.
                        // Menubar-only apps (LSUIElement=true) can't use
                        // SwiftUI CommandGroup, so this + the statusbar
                        // menu item are the only accessible entry points.
                        Button {
                            if let delegate = NSApp.delegate as? AppDelegate {
                                delegate.triggerUpdateCheck()
                            }
                        } label: {
                            Label(String(localized: "settings.checkForUpdates", defaultValue: "Check for Updates"), systemImage: "arrow.down.circle")
                        }
                    }
                    .padding(8)
                }

                GroupBox(String(localized: "settings.retention", defaultValue: "Retention")) {
                    VStack(alignment: .leading, spacing: 10) {
                        Text(String(localized: "settings.retention.help", defaultValue: "Delete alerts older than the chosen threshold. Event records are pruned separately by the detection engine's retention config."))
                            .font(.caption)
                            .foregroundColor(.secondary)

                        HStack(spacing: 8) {
                            Picker(String(localized: "settings.retention.window", defaultValue: "Clear alerts older than"), selection: $retentionWindowDays) {
                                Text(String(localized: "settings.retention.7d", defaultValue: "7 days")).tag(7)
                                Text(String(localized: "settings.retention.30d", defaultValue: "30 days")).tag(30)
                                Text(String(localized: "settings.retention.90d", defaultValue: "90 days")).tag(90)
                                Text(String(localized: "settings.retention.365d", defaultValue: "1 year")).tag(365)
                            }
                            .labelsHidden()
                            .frame(width: 140)

                            Button(role: .destructive) {
                                retentionConfirmShown = true
                            } label: {
                                Label(String(localized: "settings.retention.clear", defaultValue: "Clear Now"), systemImage: "trash")
                            }
                            .confirmationDialog(
                                String(localized: "settings.retention.confirmTitle", defaultValue: "Delete alerts older than \(retentionWindowDays) days?"),
                                isPresented: $retentionConfirmShown,
                                titleVisibility: .visible
                            ) {
                                Button(String(localized: "settings.retention.confirm", defaultValue: "Delete"), role: .destructive) {
                                    Task { await appState.pruneAlerts(olderThanDays: retentionWindowDays) }
                                }
                            } message: {
                                Text(String(
                                    localized: "settings.retention.confirmBody",
                                    defaultValue: "This removes alert rows from the local database. Events are not affected. Cannot be undone."
                                ))
                            }

                            if let result = appState.lastPruneResult {
                                Text(result)
                                    .font(.caption)
                                    .foregroundColor(.secondary)
                            }
                        }
                    }
                    .padding(8)
                }

                Spacer()
            }
            .padding(4)
        }
    }

    // MARK: - AI Backend

    private var llmTab: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                GroupBox(String(localized: "settings.llmEnable", defaultValue: "AI Backend")) {
                    VStack(alignment: .leading, spacing: 12) {
                        Toggle(String(localized: "settings.llmEnabled", defaultValue: "Enable AI-powered analysis"), isOn: $llmEnabled)
                            .onChange(of: llmEnabled) { _ in syncLLMConfig() }

                        if llmEnabled {
                            Picker(String(localized: "settings.llmProvider", defaultValue: "Provider"), selection: $llmProvider) {
                                Text(String(localized: "settings.llm.providerOllama", defaultValue: "Ollama (Local/Remote)")).tag("ollama")
                                Text(String(localized: "settings.llm.providerOpenAI", defaultValue: "OpenAI Compatible")).tag("openai")
                                Text(String(localized: "settings.llm.providerClaude", defaultValue: "Anthropic Claude")).tag("claude")
                                Text(String(localized: "settings.llm.providerMistral", defaultValue: "Mistral AI")).tag("mistral")
                                Text(String(localized: "settings.llm.providerGemini", defaultValue: "Google Gemini")).tag("gemini")
                            }
                            // Order matters: load the new provider's key into
                            // llmAPIKey FIRST, otherwise syncLLMConfig below
                            // would stamp the previous provider's key into
                            // the newly-selected provider's Keychain slot.
                            .onChange(of: llmProvider) { _ in
                                loadAPIKeyForProvider()
                                syncLLMConfig()
                            }

                            Divider()

                            switch llmProvider {
                            case "ollama":  ollamaSettings
                            case "openai":  openaiSettings
                            case "claude":  claudeSettings
                            case "mistral": mistralSettings
                            case "gemini":  geminiSettings
                            default:        ollamaSettings
                            }
                        }
                    }
                    .padding(8)
                }

                if llmEnabled {
                    GroupBox(String(localized: "settings.llmInfo", defaultValue: "How it works")) {
                        VStack(alignment: .leading, spacing: 8) {
                            Text(String(localized: "settings.llmInfoDesc", defaultValue: "The AI backend powers four features: natural language threat hunting, investigation summaries, detection rule generation, and defense recommendations."))
                                .font(.caption)
                                .foregroundColor(.secondary)

                            if llmProvider == "ollama" && (llmOllamaURL.contains("localhost") || llmOllamaURL.contains("127.0.0.1")) {
                                Text(String(localized: "settings.llmLocalPrivacy", defaultValue: "Running locally. No data leaves your machine."))
                                    .font(.caption)
                                    .foregroundColor(.green)
                            } else {
                                Text(String(localized: "settings.llmCloudPrivacy", defaultValue: "Sensitive data (usernames, private IPs, hostnames) is automatically redacted before sending."))
                                    .font(.caption)
                                    .foregroundColor(.orange)
                            }

                            Text(String(localized: "settings.llmRestart", defaultValue: "Restart the detection engine (SIGHUP) to apply changes."))
                                .font(.caption)
                                .foregroundColor(.secondary)
                        }
                        .padding(8)
                    }
                }

                Spacer()
            }
            .padding(4)
        }
        .onAppear {
            // Populate the SecureField from the Keychain on first render.
            // Without this, the field always starts blank even when the
            // user has already configured a key — they'd be tricked into
            // thinking nothing is stored and re-type.
            loadAPIKeyForProvider()
        }
    }

    private var ollamaSettings: some View {
        VStack(alignment: .leading, spacing: 8) {
            VStack(alignment: .leading, spacing: 4) {
                Text(String(localized: "settings.llmOllamaURL", defaultValue: "Ollama URL"))
                    .font(.caption).fontWeight(.medium)
                TextField("http://localhost:11434", text: $llmOllamaURL)
                    .textFieldStyle(.roundedBorder)
                    .font(.caption)
                    .onChange(of: llmOllamaURL) { _ in syncLLMConfig() }
            }

            VStack(alignment: .leading, spacing: 4) {
                Text(String(localized: "settings.llmOllamaModel", defaultValue: "Model"))
                    .font(.caption).fontWeight(.medium)
                TextField("llama3.1:8b", text: $llmOllamaModel)
                    .textFieldStyle(.roundedBorder)
                    .font(.caption)
                    .onChange(of: llmOllamaModel) { _ in syncLLMConfig() }
            }

            VStack(alignment: .leading, spacing: 4) {
                Text(String(localized: "settings.llmOllamaAPIKey", defaultValue: "API Key (optional, for remote instances)"))
                    .font(.caption).fontWeight(.medium)
                SecureField(String(localized: "settings.llmOllamaAPIKeyPlaceholder", defaultValue: "Leave blank for local"), text: $llmAPIKey)
                    .textFieldStyle(.roundedBorder)
                    .font(.caption)
                    .onChange(of: llmAPIKey) { _ in syncLLMConfig() }
            }

            Text(String(localized: "settings.llmOllamaHelp", defaultValue: "Local: install from ollama.com, run: ollama pull \(llmOllamaModel). Remote: enter the URL and API key of your Ollama server."))
                .font(.caption2)
                .foregroundColor(.secondary)
        }
    }

    private var openaiSettings: some View {
        VStack(alignment: .leading, spacing: 8) {
            VStack(alignment: .leading, spacing: 4) {
                Text(String(localized: "settings.llmOpenAIURL", defaultValue: "API Base URL"))
                    .font(.caption).fontWeight(.medium)
                TextField("https://api.openai.com/v1", text: $llmOpenAIURL)
                    .textFieldStyle(.roundedBorder)
                    .font(.caption)
                    .onChange(of: llmOpenAIURL) { _ in syncLLMConfig() }
            }

            VStack(alignment: .leading, spacing: 4) {
                Text(String(localized: "settings.llmAPIKey", defaultValue: "API Key"))
                    .font(.caption).fontWeight(.medium)
                SecureField("sk-...", text: $llmAPIKey)
                    .textFieldStyle(.roundedBorder)
                    .font(.caption)
                    .onChange(of: llmAPIKey) { _ in syncLLMConfig() }
            }

            VStack(alignment: .leading, spacing: 4) {
                Text(String(localized: "settings.llmModel", defaultValue: "Model"))
                    .font(.caption).fontWeight(.medium)
                TextField("gpt-4o-mini", text: $llmModel)
                    .textFieldStyle(.roundedBorder)
                    .font(.caption)
                    .onChange(of: llmModel) { _ in syncLLMConfig() }
            }

            Text(String(localized: "settings.llmOpenAIHelp", defaultValue: "Works with OpenAI, Azure OpenAI, or any OpenAI-compatible endpoint (LM Studio, vLLM, etc.)"))
                .font(.caption2)
                .foregroundColor(.secondary)
        }
    }

    private var claudeSettings: some View {
        VStack(alignment: .leading, spacing: 8) {
            VStack(alignment: .leading, spacing: 4) {
                Text(String(localized: "settings.llmClaudeKey", defaultValue: "Anthropic API Key"))
                    .font(.caption).fontWeight(.medium)
                SecureField("sk-ant-...", text: $llmAPIKey)
                    .textFieldStyle(.roundedBorder)
                    .font(.caption)
                    .onChange(of: llmAPIKey) { _ in syncLLMConfig() }
            }

            VStack(alignment: .leading, spacing: 4) {
                Text(String(localized: "settings.llmClaudeModel", defaultValue: "Model"))
                    .font(.caption).fontWeight(.medium)
                TextField("claude-sonnet-4-20250514", text: $llmModel)
                    .textFieldStyle(.roundedBorder)
                    .font(.caption)
                    .onChange(of: llmModel) { _ in syncLLMConfig() }
            }

            Text(String(localized: "settings.llmClaudeHelp", defaultValue: "Get an API key from console.anthropic.com"))
                .font(.caption2)
                .foregroundColor(.secondary)
        }
    }

    private var mistralSettings: some View {
        VStack(alignment: .leading, spacing: 8) {
            VStack(alignment: .leading, spacing: 4) {
                Text(String(localized: "settings.llmMistralKey", defaultValue: "Mistral API Key"))
                    .font(.caption).fontWeight(.medium)
                SecureField("...", text: $llmAPIKey)
                    .textFieldStyle(.roundedBorder)
                    .font(.caption)
                    .onChange(of: llmAPIKey) { _ in syncLLMConfig() }
            }

            VStack(alignment: .leading, spacing: 4) {
                Text(String(localized: "settings.llmMistralModel", defaultValue: "Model"))
                    .font(.caption).fontWeight(.medium)
                TextField("mistral-small-latest", text: $llmModel)
                    .textFieldStyle(.roundedBorder)
                    .font(.caption)
                    .onChange(of: llmModel) { _ in syncLLMConfig() }
            }

            Text(String(localized: "settings.llmMistralHelp", defaultValue: "Get an API key from console.mistral.ai"))
                .font(.caption2)
                .foregroundColor(.secondary)
        }
    }

    private var geminiSettings: some View {
        VStack(alignment: .leading, spacing: 8) {
            VStack(alignment: .leading, spacing: 4) {
                Text(String(localized: "settings.llmGeminiKey", defaultValue: "Google AI API Key"))
                    .font(.caption).fontWeight(.medium)
                SecureField("AIza...", text: $llmAPIKey)
                    .textFieldStyle(.roundedBorder)
                    .font(.caption)
                    .onChange(of: llmAPIKey) { _ in syncLLMConfig() }
            }

            VStack(alignment: .leading, spacing: 4) {
                Text(String(localized: "settings.llmGeminiModel", defaultValue: "Model"))
                    .font(.caption).fontWeight(.medium)
                TextField("gemini-2.0-flash", text: $llmModel)
                    .textFieldStyle(.roundedBorder)
                    .font(.caption)
                    .onChange(of: llmModel) { _ in syncLLMConfig() }
            }

            Text(String(localized: "settings.llmGeminiHelp", defaultValue: "Get an API key from aistudio.google.com"))
                .font(.caption2)
                .foregroundColor(.secondary)
        }
    }

    // MARK: - Keychain ↔ UI plumbing

    /// Map the current provider string to its SecretsStore key.
    private func secretKeyForCurrentProvider() -> SecretKey? {
        switch llmProvider {
        case "ollama":  return .ollamaAPIKey
        case "openai":  return .openaiAPIKey
        case "claude":  return .claudeAPIKey
        case "mistral": return .mistralAPIKey
        case "gemini":  return .geminiAPIKey
        default:        return nil
        }
    }

    /// Pull the API key for the currently-selected provider out of the
    /// Keychain into the bound @State field. Called on view appear and
    /// whenever the provider changes. Silent on failure — UI shows
    /// "empty" which is indistinguishable from "not set", which matches
    /// user expectation.
    private func loadAPIKeyForProvider() {
        guard let key = secretKeyForCurrentProvider() else {
            llmAPIKey = ""
            return
        }
        let loaded = (try? secrets.get(key)) ?? nil
        llmAPIKey = loaded ?? ""
    }

    /// Persist the current llmAPIKey into the Keychain for the selected
    /// provider. Called from `syncLLMConfig()` on every config edit.
    /// An empty value deletes the slot (matches SecretsStore.set semantics).
    private func saveAPIKeyToKeychain() {
        guard let key = secretKeyForCurrentProvider() else { return }
        try? secrets.set(key, value: llmAPIKey)
    }

    /// Write LLM config to a JSON file the daemon can read.
    ///
    /// The Keychain is the authoritative store for API keys in v1.3.5+ —
    /// but until the sysext ships with a shared `keychain-access-groups`
    /// entitlement, it still reads the key from this JSON file. Writing
    /// both keeps the sysext working today and sets us up to drop the
    /// JSON-side secret once the entitlement lands.
    private func syncLLMConfig() {
        saveAPIKeyToKeychain()

        let configDir = NSHomeDirectory() + "/Library/Application Support/MacCrab"
        try? FileManager.default.createDirectory(atPath: configDir, withIntermediateDirectories: true)
        let configPath = configDir + "/llm_config.json"

        var config: [String: Any] = [
            "enabled": llmEnabled,
            "provider": llmProvider,
            "ollama_url": llmOllamaURL,
            "ollama_model": llmOllamaModel,
        ]

        switch llmProvider {
        case "ollama":
            if !llmAPIKey.isEmpty { config["ollama_api_key"] = llmAPIKey }
        case "openai":
            config["openai_url"] = llmOpenAIURL
            config["openai_api_key"] = llmAPIKey
            config["openai_model"] = llmModel.isEmpty ? "gpt-4o-mini" : llmModel
        case "claude":
            config["claude_api_key"] = llmAPIKey
            config["claude_model"] = llmModel.isEmpty ? "claude-sonnet-4-20250514" : llmModel
        case "mistral":
            config["mistral_api_key"] = llmAPIKey
            config["mistral_model"] = llmModel.isEmpty ? "mistral-small-latest" : llmModel
        case "gemini":
            config["gemini_api_key"] = llmAPIKey
            config["gemini_model"] = llmModel.isEmpty ? "gemini-2.0-flash" : llmModel
        default: break
        }

        if let data = try? JSONSerialization.data(withJSONObject: config) {
            try? data.write(to: URL(fileURLWithPath: configPath))
        }

        // Update AppState so UI reflects immediately
        appState.llmStatus.isConfigured = llmEnabled
        appState.llmStatus.provider = llmProvider
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

                Text("v1.3.4")
                    .font(.caption)
                    .foregroundColor(.secondary)

                Divider()
                    .frame(width: 200)

                VStack(spacing: 4) {
                    Text(String(localized: "settings.aboutStats", defaultValue: "7 event sources | 8 detection layers | 304 rules"))
                        .font(.caption)
                        .foregroundColor(.secondary)
                    Text(String(localized: "settings.aboutLicense", defaultValue: "Apache 2.0 (code)  |  DRL 1.1 (rules)"))
                        .font(.caption)
                        .foregroundColor(.secondary)
                }

                Spacer()

                Text(String(localized: "about.madeWithLove", defaultValue: "Made with love and tokens in Ireland"))
                    .font(.caption)
                    .foregroundColor(.secondary)
                    .padding(.bottom, 8)
            }
            .padding(4)
        }
    }

    // MARK: - Private

    private var currentDatabaseSize: String {
        let path = databasePath
        guard let attrs = try? FileManager.default.attributesOfItem(atPath: path),
              let size = attrs[.size] as? UInt64 else { return "—" }
        return ByteCountFormatter.string(fromByteCount: Int64(size), countStyle: .file)
    }

    private var isDatabaseNearLimit: Bool {
        let path = databasePath
        guard let attrs = try? FileManager.default.attributesOfItem(atPath: path),
              let size = attrs[.size] as? UInt64 else { return false }
        return size > UInt64(maxDatabaseSizeMB) * 800_000 // warn at 80%
    }

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
