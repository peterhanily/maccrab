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
    // Note: legacy @AppStorage keys "autoQuarantine", "autoKill", and
    // "autoBlock" were removed in v1.6.19. Their UI toggles wrote to user
    // defaults but no daemon code consumed the values, so the toggles
    // produced a false sense of security. The Response Actions tab already
    // exposes per-rule action configuration that IS wired into
    // ResponseEngine — that's the canonical surface.

    // v1.8.0: per-tier storage budgets replace the singleton
    // (maxDatabaseSizeMB, retentionDays). Defaults match
    // DaemonConfig.StorageConfig in MacCrabAgentKit. Legacy keys are
    // migrated onto these on first appear via `migrateLegacyStorageKeys`.
    @AppStorage("storage.eventsHotTierHours")    private var eventsHotTierHours: Int = 1
    @AppStorage("storage.eventsMaxSizeMB")       private var eventsMaxSizeMB: Int = 200
    @AppStorage("storage.alertsRetentionDays")   private var alertsRetentionDays: Int = 365
    @AppStorage("storage.alertsMaxSizeMB")       private var alertsMaxSizeMB: Int = 100
    @AppStorage("storage.campaignsRetentionDays") private var campaignsRetentionDays: Int = 365
    @AppStorage("storage.campaignsMaxSizeMB")    private var campaignsMaxSizeMB: Int = 50

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

    // Pending debounced webhook sync. onChange fires once per keystroke;
    // without this debounce, typing a 30-char webhook URL would write the
    // config file + SIGHUP the daemon 30 times in quick succession (each
    // SIGHUP triggers a /Users walk in NotificationIntegrations).
    @State private var pendingWebhookSync: Task<Void, Never>?

    // v1.6.21 surface E: LLM "Test Connection" button state. nil =
    // hasn't been tested in this session; .testing = in flight; .ok /
    // .failure = result. Resets on provider/URL/key change.
    @State private var llmTestStatus: LLMTestStatus = .untested
    private enum LLMTestStatus: Equatable {
        case untested
        case testing
        case ok(String)        // detail (e.g. "Connected to ollama")
        case failure(String)   // reason
    }

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
                GroupBox(String(localized: "settings.storage", defaultValue: "Storage")) {
                    VStack(alignment: .leading, spacing: 12) {

                        // Event firehose — short window, small budget.
                        // The 1h default reflects that events are firehose
                        // data with near-zero half-life past correlation.
                        storageRow(
                            label: String(localized: "settings.events.label", defaultValue: "Event firehose"),
                            help: String(localized: "settings.events.help", defaultValue: "Last hour of raw activity for live rules. Aggregates carry forward what's worth keeping."),
                            stepperValue: "\(eventsHotTierHours)h",
                            stepperBinding: $eventsHotTierHours,
                            stepperRange: 1...24,
                            stepperStep: 1,
                            sizeBinding: $eventsMaxSizeMB,
                            sizeRange: 100...2000,
                            sizeStep: 100,
                            currentSize: currentSize(databaseFile: "events.db"),
                            currentBytes: currentBytes(databaseFile: "events.db"),
                            capMB: eventsMaxSizeMB
                        )

                        Divider()

                        // Alert history — long window, generous budget.
                        // 365 days of alerts is small (~10 KB/alert × ~50/day
                        // × 365 = 180 MB) and forensically valuable.
                        storageRow(
                            label: String(localized: "settings.alerts.label", defaultValue: "Alert history"),
                            help: String(localized: "settings.alerts.help", defaultValue: "Detections fired by MacCrab. Survives any event-firehose prune."),
                            stepperValue: "\(alertsRetentionDays)d",
                            stepperBinding: $alertsRetentionDays,
                            stepperRange: 30...1095,
                            stepperStep: 30,
                            sizeBinding: $alertsMaxSizeMB,
                            sizeRange: 50...500,
                            sizeStep: 50,
                            currentSize: currentSize(databaseFile: "alerts.db"),
                            currentBytes: currentBytes(databaseFile: "alerts.db"),
                            capMB: alertsMaxSizeMB
                        )

                        Divider()

                        // Campaign history — even longer; campaigns are tiny.
                        storageRow(
                            label: String(localized: "settings.campaigns.label", defaultValue: "Campaign history"),
                            help: String(localized: "settings.campaigns.help", defaultValue: "Multi-step attack chains MacCrab has correlated."),
                            stepperValue: "\(campaignsRetentionDays)d",
                            stepperBinding: $campaignsRetentionDays,
                            stepperRange: 30...1095,
                            stepperStep: 30,
                            sizeBinding: $campaignsMaxSizeMB,
                            sizeRange: 25...200,
                            sizeStep: 25,
                            currentSize: currentSize(databaseFile: "campaigns.db"),
                            currentBytes: currentBytes(databaseFile: "campaigns.db"),
                            capMB: campaignsMaxSizeMB
                        )
                    }
                    .padding(8)
                    .onChange(of: eventsHotTierHours)    { _ in syncStorageOverrides() }
                    .onChange(of: eventsMaxSizeMB)       { _ in syncStorageOverrides() }
                    .onChange(of: alertsRetentionDays)   { _ in syncStorageOverrides() }
                    .onChange(of: alertsMaxSizeMB)       { _ in syncStorageOverrides() }
                    .onChange(of: campaignsRetentionDays) { _ in syncStorageOverrides() }
                    .onChange(of: campaignsMaxSizeMB)    { _ in syncStorageOverrides() }
                    .onAppear { migrateLegacyStorageKeys() }
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

                // The "Auto-Response" GroupBox (autoQuarantine/autoKill/
                // autoBlock toggles) was removed in v1.6.19. Those toggles
                // wrote to UserDefaults but no daemon code consumed them.
                // Per-rule auto-actions live in the Response Actions tab,
                // which IS wired into ResponseEngine.

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
                            .onChange(of: webhookMinSeverity) { _ in scheduleWebhookSync() }
                        }

                        Divider()

                        VStack(alignment: .leading, spacing: 4) {
                            Text(String(localized: "settings.slackWebhook", defaultValue: "Slack Webhook URL"))
                                .font(.caption).fontWeight(.medium)
                            TextField("https://hooks.slack.com/services/...", text: $webhookSlackURL)
                                .textFieldStyle(.roundedBorder)
                                .font(.caption)
                                .onChange(of: webhookSlackURL) { _ in scheduleWebhookSync() }
                        }

                        VStack(alignment: .leading, spacing: 4) {
                            Text(String(localized: "settings.teamsWebhook", defaultValue: "Microsoft Teams Webhook URL"))
                                .font(.caption).fontWeight(.medium)
                            TextField("https://outlook.office.com/webhook/...", text: $webhookTeamsURL)
                                .textFieldStyle(.roundedBorder)
                                .font(.caption)
                                .onChange(of: webhookTeamsURL) { _ in scheduleWebhookSync() }
                        }

                        VStack(alignment: .leading, spacing: 4) {
                            Text(String(localized: "settings.discordWebhook", defaultValue: "Discord Webhook URL"))
                                .font(.caption).fontWeight(.medium)
                            TextField("https://discord.com/api/webhooks/...", text: $webhookDiscordURL)
                                .textFieldStyle(.roundedBorder)
                                .font(.caption)
                                .onChange(of: webhookDiscordURL) { _ in scheduleWebhookSync() }
                        }

                        VStack(alignment: .leading, spacing: 4) {
                            Text(String(localized: "settings.pagerdutyKey", defaultValue: "PagerDuty Routing Key"))
                                .font(.caption).fontWeight(.medium)
                            TextField("e93facc04764012d7bfb002500d5d1a6...", text: $webhookPagerDutyKey)
                                .textFieldStyle(.roundedBorder)
                                .font(.caption)
                                .onChange(of: webhookPagerDutyKey) { _ in scheduleWebhookSync() }
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

                        // v1.7.9: brew-install caption. When MacCrab.app
                        // lives under /Caskroom/ we've already disabled
                        // Sparkle's automatic background checks (see
                        // MacCrabApp.updaterController init) to prevent the
                        // v1.6.13 → v1.7.5 drift incident. Surface the
                        // recommendation so the user knows where to
                        // upgrade from.
                        if MacCrabApp.isBrewInstalled {
                            Text(String(localized: "settings.brewInstalled.hint",
                                        defaultValue: "Installed via Homebrew. Background auto-update is off; upgrade with `brew upgrade --cask maccrab`. Manual checks above still work."))
                                .font(.caption)
                                .foregroundColor(.secondary)
                                .fixedSize(horizontal: false, vertical: true)
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
                            // Invalidate the test result on any config edit
                            // so a stale "OK" doesn't mislead after the user
                            // changes the URL/key/model.
                            Color.clear.frame(height: 0)
                                .onChange(of: llmProvider) { _ in llmTestStatus = .untested }
                                .onChange(of: llmAPIKey) { _ in llmTestStatus = .untested }
                                .onChange(of: llmOllamaURL) { _ in llmTestStatus = .untested }
                                .onChange(of: llmOllamaModel) { _ in llmTestStatus = .untested }
                                .onChange(of: llmOpenAIURL) { _ in llmTestStatus = .untested }
                                .onChange(of: llmModel) { _ in llmTestStatus = .untested }

                            Divider()

                            // v1.6.21 surface E: Test Connection. Calls
                            // LLMService.makeFromConfig with the current
                            // editor state and reports whether the backend
                            // is reachable. Completes Tier 3 #15 from the
                            // best-in-show roadmap.
                            HStack(spacing: 8) {
                                Button {
                                    Task { await testLLMConnection() }
                                } label: {
                                    if case .testing = llmTestStatus {
                                        ProgressView()
                                            .controlSize(.small)
                                            .scaleEffect(0.7)
                                    }
                                    Text(String(localized: "settings.llm.testConnection", defaultValue: "Test Connection"))
                                }
                                .disabled(llmTestStatus == .testing)
                                .controlSize(.small)
                                .accessibilityLabel("Test LLM backend connection")

                                switch llmTestStatus {
                                case .untested:
                                    EmptyView()
                                case .testing:
                                    Text(String(localized: "settings.llm.testing", defaultValue: "Connecting…"))
                                        .font(.caption)
                                        .foregroundColor(.secondary)
                                case .ok(let detail):
                                    Label(detail, systemImage: "checkmark.circle.fill")
                                        .labelStyle(.titleAndIcon)
                                        .foregroundColor(.green)
                                        .font(.caption)
                                case .failure(let reason):
                                    Label(reason, systemImage: "xmark.octagon.fill")
                                        .labelStyle(.titleAndIcon)
                                        .foregroundColor(.red)
                                        .font(.caption)
                                }
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
                TextField("claude-sonnet-4-6", text: $llmModel)
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
    /// v1.6.21 surface E: probe the LLM backend without firing a real
    /// alert. Builds an LLMConfig from the editor state, calls
    /// `LLMService.makeFromConfig` (which does an availability check),
    /// and surfaces the bool result inline. nil = unreachable / wrong
    /// key / disabled; non-nil = backend responded.
    @MainActor
    private func testLLMConnection() async {
        llmTestStatus = .testing
        // Build a transient LLMConfig from the editor state. Don't write
        // to disk — Test should be side-effect-free and read-only.
        var cfg = LLMConfig()
        cfg.enabled = true // bypass the early-return in makeFromConfig
        cfg.provider = LLMProvider(rawValue: llmProvider) ?? .ollama
        cfg.ollamaURL = llmOllamaURL
        cfg.ollamaModel = llmOllamaModel
        cfg.openaiURL = llmOpenAIURL
        switch cfg.provider {
        case .ollama:
            if !llmAPIKey.isEmpty { cfg.ollamaAPIKey = llmAPIKey }
        case .openai:
            cfg.openaiAPIKey = llmAPIKey
            cfg.openaiModel = llmModel.isEmpty ? "gpt-4o-mini" : llmModel
        case .claude:
            cfg.claudeAPIKey = llmAPIKey
            cfg.claudeModel = llmModel.isEmpty ? "claude-sonnet-4-6" : llmModel
        case .mistral:
            cfg.mistralAPIKey = llmAPIKey
            cfg.mistralModel = llmModel.isEmpty ? "mistral-small-latest" : llmModel
        case .gemini:
            cfg.geminiAPIKey = llmAPIKey
            cfg.geminiModel = llmModel.isEmpty ? "gemini-2.0-flash" : llmModel
        }
        let svc = await LLMService.makeFromConfig(cfg)
        if svc != nil {
            llmTestStatus = .ok("Connected via \(llmProvider)")
        } else {
            // makeFromConfig returns nil for: disabled (we set enabled),
            // missing API key (we set keys), or backend.isAvailable() false.
            // Empty key is the most actionable failure for the user.
            let reason: String
            switch cfg.provider {
            case .ollama:
                reason = "Backend unreachable — check the Ollama URL"
            default:
                if llmAPIKey.isEmpty {
                    reason = "Missing API key for \(llmProvider)"
                } else {
                    reason = "Backend unreachable — check provider/URL/key"
                }
            }
            llmTestStatus = .failure(reason)
        }
    }

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
            config["claude_model"] = llmModel.isEmpty ? "claude-sonnet-4-6" : llmModel
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

        // Drop the user-side LLM stack so the next triage call rebuilds
        // from this freshly-written config rather than waiting for the
        // 30 s re-check window.
        appState.invalidateLLMConfigCache()
    }

    /// v1.6.14 / v1.8.0: write the per-tier storage block to
    /// `~/Library/Application Support/MacCrab/user_overrides.json` and
    /// SIGHUP the sysext so the new values take effect on the next sweep
    /// tick. Until v1.6.14 landed, the sliders wrote only to @AppStorage
    /// and the daemon never saw them. v1.8.0 expanded the payload from
    /// (maxDatabaseSizeMB, retentionDays) to the full storage block.
    ///
    /// The daemon overlays this file on top of its own
    /// `daemon_config.json` in `DaemonConfig.applyUserOverrides`. The
    /// file is restricted to the storage block so a writable user-home
    /// file can never perturb security-sensitive settings (thresholds,
    /// outputs, LLM provider).
    private func syncStorageOverrides() {
        let configDir = NSHomeDirectory() + "/Library/Application Support/MacCrab"
        try? FileManager.default.createDirectory(atPath: configDir, withIntermediateDirectories: true)
        let path = configDir + "/user_overrides.json"

        let payload: [String: Any] = [
            "storage": [
                "eventsHotTierHours":    eventsHotTierHours,
                "eventsMaxSizeMB":       eventsMaxSizeMB,
                "alertsRetentionDays":   alertsRetentionDays,
                "alertsMaxSizeMB":       alertsMaxSizeMB,
                "campaignsRetentionDays": campaignsRetentionDays,
                "campaignsMaxSizeMB":    campaignsMaxSizeMB,
            ]
        ]
        guard let data = try? JSONSerialization.data(
            withJSONObject: payload,
            options: [.prettyPrinted, .sortedKeys]
        ) else { return }

        // Atomic write so the daemon's overlay reader never catches
        // a half-written file during the 50 ms between slider moves.
        let tmp = path + ".tmp"
        do {
            try data.write(to: URL(fileURLWithPath: tmp))
            _ = try? FileManager.default.removeItem(atPath: path)
            try FileManager.default.moveItem(atPath: tmp, toPath: path)
        } catch {
            return
        }

        // Nudge the sysext to reload. Best-effort: if the sysext
        // isn't running or pkill isn't permitted we silently fall
        // through — the new value will still land the next time
        // the daemon starts or on the next hourly tick (the size-
        // cap timer now reads `state.maxDatabaseSizeMB` live, but
        // only the SIGHUP path reloads it from disk).
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/pkill")
        task.arguments = ["-HUP", "com.maccrab.agent"]
        task.standardOutput = Pipe()
        task.standardError = Pipe()
        try? task.run()
    }

    /// Debounced wrapper for syncWebhookConfig. Cancels any pending sync
    /// task and reschedules 500 ms in the future, so a user typing a 30-
    /// character webhook URL produces ONE file write + SIGHUP, not 30.
    /// Without this, every keystroke would trigger a /Users walk inside
    /// NotificationIntegrations.reloadConfig — a real DoS vector against
    /// the daemon's main loop.
    private func scheduleWebhookSync() {
        pendingWebhookSync?.cancel()
        pendingWebhookSync = Task {
            // v1.6.21 HIGH fix: don't swallow CancellationError with try?.
            // Pre-fix, a cancelled sleep would fall through to the
            // syncWebhookConfig() call and write a partial/stale config.
            // Now: catch CancellationError explicitly and bail.
            do {
                try await Task.sleep(nanoseconds: 500_000_000)
            } catch {
                return // Cancelled — a newer keystroke is pending
            }
            guard !Task.isCancelled else { return }
            await MainActor.run { self.syncWebhookConfig() }
        }
    }

    /// v1.6.19: write the four webhook URLs + the minimum severity to
    /// `~/Library/Application Support/MacCrab/notifications.json` in the
    /// `NotificationIntegrations.Config` shape, then SIGHUP the daemon.
    /// Closes a wire-the-orphans gap (Pass 1 audit): pre-v1.6.19 the
    /// SettingsView TextFields wrote to @AppStorage but no daemon code
    /// consumed the values, so configured Slack/Teams/Discord/PagerDuty
    /// webhooks never fired.
    private func syncWebhookConfig() {
        let configDir = NSHomeDirectory() + "/Library/Application Support/MacCrab"
        try? FileManager.default.createDirectory(atPath: configDir, withIntermediateDirectories: true)
        let path = configDir + "/notifications.json"

        var payload: [String: Any] = [
            "minimumSeverity": webhookMinSeverity
        ]
        let slack = webhookSlackURL.trimmingCharacters(in: .whitespacesAndNewlines)
        if !slack.isEmpty {
            payload["slack"] = ["webhookURL": slack]
        }
        let teams = webhookTeamsURL.trimmingCharacters(in: .whitespacesAndNewlines)
        if !teams.isEmpty {
            payload["teams"] = ["webhookURL": teams]
        }
        let discord = webhookDiscordURL.trimmingCharacters(in: .whitespacesAndNewlines)
        if !discord.isEmpty {
            payload["discord"] = ["webhookURL": discord]
        }
        let pd = webhookPagerDutyKey.trimmingCharacters(in: .whitespacesAndNewlines)
        if !pd.isEmpty {
            payload["pagerduty"] = ["routingKey": pd, "severity": "error"]
        }

        guard let data = try? JSONSerialization.data(
            withJSONObject: payload,
            options: [.prettyPrinted, .sortedKeys]
        ) else { return }

        // Atomic write — same pattern as syncStorageOverrides.
        let tmp = path + ".tmp"
        do {
            try data.write(to: URL(fileURLWithPath: tmp))
            _ = try? FileManager.default.removeItem(atPath: path)
            try FileManager.default.moveItem(atPath: tmp, toPath: path)
        } catch {
            return
        }

        // SIGHUP the sysext so NotificationIntegrations.reloadConfig
        // picks up the new file. Best-effort.
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/pkill")
        task.arguments = ["-HUP", "com.maccrab.agent"]
        task.standardOutput = Pipe()
        task.standardError = Pipe()
        try? task.run()
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

                // v1.7.10: read version dynamically from Info.plist so this
                // line tracks every release automatically. Pre-fix it was
                // hardcoded "v1.3.4" and had drifted ~20 releases out of date.
                Text(verbatim: "v\(Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "?")")
                    .font(.caption)
                    .foregroundColor(.secondary)

                Divider()
                    .frame(width: 200)

                VStack(spacing: 4) {
                    Text(String(localized: "settings.aboutStats", defaultValue: "19 event sources | 5 detection layers | 424 rules"))
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

    /// v1.8.0: per-DB-file size lookup. Splitting alerts and campaigns
    /// into their own SQLite files means each tier gets its own current-
    /// size readout in Settings. Reads from whichever path
    /// `databasePathForFile(_:)` resolves to (system if root daemon owns
    /// it, user dir for non-root dev daemon).
    private func currentSize(databaseFile name: String) -> String {
        let bytes = currentBytes(databaseFile: name)
        guard bytes > 0 else { return "—" }
        return ByteCountFormatter.string(fromByteCount: Int64(bytes), countStyle: .file)
    }

    private func currentBytes(databaseFile name: String) -> UInt64 {
        let path = databasePathForFile(name)
        guard let attrs = try? FileManager.default.attributesOfItem(atPath: path),
              let size = attrs[.size] as? UInt64 else { return 0 }
        return size
    }

    private func databasePathForFile(_ name: String) -> String {
        let fm = FileManager.default
        let userDir = fm.urls(for: .applicationSupportDirectory, in: .userDomainMask)
            .first.map { $0.appendingPathComponent("MacCrab").path }
            ?? NSHomeDirectory() + "/Library/Application Support/MacCrab"
        let systemDir = "/Library/Application Support/MacCrab"

        let userPath = userDir + "/" + name
        let systemPath = systemDir + "/" + name
        let userExists = fm.fileExists(atPath: userPath)
        let systemReadable = fm.isReadableFile(atPath: systemPath)

        if userExists && systemReadable {
            let userMod = (try? fm.attributesOfItem(atPath: userPath))?[.modificationDate] as? Date
            let sysMod  = (try? fm.attributesOfItem(atPath: systemPath))?[.modificationDate] as? Date
            if let s = sysMod, let u = userMod, s >= u {
                return systemPath
            }
            return userPath
        }
        if systemReadable { return systemPath }
        if userExists { return userPath }
        return systemPath
    }

    /// One row in the Storage GroupBox. Three of these stack with dividers
    /// between them — events / alerts / campaigns.
    @ViewBuilder
    private func storageRow(
        label: String,
        help: String,
        stepperValue: String,
        stepperBinding: Binding<Int>,
        stepperRange: ClosedRange<Int>,
        stepperStep: Int,
        sizeBinding: Binding<Int>,
        sizeRange: ClosedRange<Int>,
        sizeStep: Int,
        currentSize: String,
        currentBytes: UInt64,
        capMB: Int
    ) -> some View {
        let nearLimit = currentBytes > UInt64(capMB) * 800_000  // 80% warning
        VStack(alignment: .leading, spacing: 4) {
            Text(label).font(.headline)
            HStack(spacing: 12) {
                Stepper(stepperValue, value: stepperBinding, in: stepperRange, step: stepperStep)
                    .frame(maxWidth: 180, alignment: .leading)
                Text("·").foregroundColor(.secondary)
                Stepper("≤ \(sizeBinding.wrappedValue) MB", value: sizeBinding, in: sizeRange, step: sizeStep)
                    .frame(maxWidth: 200, alignment: .leading)
                Spacer()
                Text(currentSize)
                    .font(.system(.caption, design: .monospaced))
                    .foregroundColor(nearLimit ? .orange : .secondary)
            }
            Text(help).font(.caption).foregroundColor(.secondary)
        }
    }

    /// v1.8.0: migrate legacy @AppStorage keys (retentionDays,
    /// maxDatabaseSizeMB) onto the new per-tier shape on first appear.
    /// One-shot — once the new keys are non-default OR the legacy keys
    /// are absent, this becomes a no-op. After migration, the legacy
    /// keys remain in UserDefaults but nothing reads them.
    private func migrateLegacyStorageKeys() {
        let defaults = UserDefaults.standard

        // If a legacy retentionDays exists AND the new alerts/campaigns
        // keys are still at default (365), apply the legacy value.
        if let legacyRetention = defaults.object(forKey: "retentionDays") as? Int {
            if alertsRetentionDays == 365 && campaignsRetentionDays == 365 {
                alertsRetentionDays    = max(30, min(legacyRetention, 1095))
                campaignsRetentionDays = max(30, min(legacyRetention, 1095))
            }
            // Don't remove the legacy key — keep it for safety. Nothing reads it.
        }

        // Same shape for the legacy size cap.
        if let legacyCap = defaults.object(forKey: "maxDatabaseSizeMB") as? Int {
            if eventsMaxSizeMB == 200 {
                eventsMaxSizeMB = max(100, min(legacyCap, 2000))
            }
        }

        // Push the (possibly migrated) values to user_overrides.json so
        // the daemon's overlay reader sees them on the next SIGHUP / boot.
        syncStorageOverrides()
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
