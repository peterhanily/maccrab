// SettingsView.swift
// MacCrabApp
//
// Application settings view accessible via Cmd+, or the status bar menu.

import SwiftUI
import AppKit
import UserNotifications
import MacCrabCore
import MacCrabForensics
import ServiceManagement
import Sparkle
import os.log

// MARK: - SettingsView

struct SettingsView: View {
    @ObservedObject var appState: AppState
    /// v1.9 hot-fix: sysext manager passed in so the "Remove System
    /// Extension" button in the recovery group can submit an
    /// OSSystemExtensionRequest.deactivationRequest. Useful when an
    /// older sysext version is misbehaving (the v1.8.x size-cap
    /// regression class) and the operator needs a clean uninstall
    /// path that doesn't require disabling SIP.
    @ObservedObject var sysextManager: SystemExtensionManager
    @AppStorage("alertNotifications") var alertNotifications: Bool = true
    // v1.8.0: default raised to "critical" so a fresh install only
    // notifies on the most serious detections. Existing installs retain
    // whatever value is already in UserDefaults.
    @AppStorage("minAlertSeverity") var minAlertSeverity: String = "critical"
    // v1.18 agent control-plane: which MCP capability tiers an AI agent may
    // use. All OFF by default; only the human flips these. Written to
    // mcp_capabilities.json which the MCP server reads.
    @AppStorage("agentCapConfig") private var agentCapConfig: Bool = false
    @AppStorage("agentCapAuthoring") private var agentCapAuthoring: Bool = false
    @AppStorage("agentCapResponse") private var agentCapResponse: Bool = false
    // Confirm-on-enable gate for the defense-affecting tier (an agent granted
    // this can disable ES introspection → reduce detection). Security-critical.
    @State private var confirmAgentResponseTier = false
    // v1.19.1 network-enrichment privacy opt-ins. All OFF by default — MacCrab
    // is on-device by default; nothing about your machine leaves it until you
    // flip one of these. The daemon defaults match (DaemonConfig defaults are
    // false), and these same keys back the first-run prompt + the Intel card.
    @AppStorage("enrich.threatIntel")      private var enrichThreatIntel: Bool = false
    @AppStorage("enrich.vulnScan")         private var enrichVulnScan: Bool = false
    @AppStorage("enrich.packageFreshness") private var enrichPackageFreshness: Bool = false
    @AppStorage("enrich.certTransparency") private var enrichCertTransparency: Bool = false
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
    @AppStorage("storage.eventsHotTierMinutes") private var eventsHotTierMinutes: Int = 30
    @AppStorage("storage.eventsMaxSizeMB")       private var eventsMaxSizeMB: Int = 350  // match DaemonConfig default
    @AppStorage("storage.alertsRetentionDays")   private var alertsRetentionDays: Int = 365
    @AppStorage("storage.alertsMaxSizeMB")       private var alertsMaxSizeMB: Int = 100
    @AppStorage("storage.campaignsRetentionDays") private var campaignsRetentionDays: Int = 365
    @AppStorage("storage.campaignsMaxSizeMB")    private var campaignsMaxSizeMB: Int = 50

    @AppStorage("retentionWindowDays") private var retentionWindowDays: Int = 30
    /// v1.17 (issue #2): true when the OS has denied notification
    /// authorization for MacCrab. Banners now come from the app via
    /// UNUserNotificationCenter, so a denial silences them — surface it
    /// in the notifications tab with a jump to System Settings.
    @State private var notificationsOSDenied: Bool = false
    @State private var retentionConfirmShown: Bool = false
    /// v1.9.0 (audit UX-H6): in-app confirmation before submitting
    /// the deactivation request to the OS. macOS shows its own modal
    /// after submit; the dashboard ack guards against pure misclicks.
    @State private var sysextRemoveConfirmShown: Bool = false

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
    /// v1.11.0 RC2 ship-blocker fix: same debounce treatment for
    /// the alert-notification config sync. Pre-fix every onChange
    /// (toggle click + every Picker tab/click cycle) immediately
    /// fired pkill -HUP, and SIGHUP triggers an expensive retroactive
    /// scan + storage reload + rule reload. Rapid UI changes piled up
    /// parallel daemon Tasks. 500 ms debounce mirrors the webhook
    /// sync pattern.
    @State private var pendingAlertNotificationSync: Task<Void, Never>?

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

            forensicsTab
                .tabItem { Label(String(localized: "settings.forensics", defaultValue: "Forensics"), systemImage: "doc.text.magnifyingglass") }

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
                                .accessibilityHidden(true) // decorative legend dot
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
                        // 30 min default = 3× the longest sequence-rule
                        // window (10 min). Floor enforced at 15 min in
                        // the daemon — slider can't go below that.
                        storageRow(
                            label: String(localized: "settings.events.label", defaultValue: "Event firehose"),
                            help: String(localized: "settings.events.help", defaultValue: "Recent raw activity for live rules. Floor 15 min — anything shorter risks dropping events mid-sequence."),
                            stepperValue: eventsTierLabel(eventsHotTierMinutes),
                            stepperBinding: $eventsHotTierMinutes,
                            stepperRange: 15...1440,
                            stepperStep: 15,
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
                    .onChange(of: eventsHotTierMinutes) { _ in syncStorageOverrides() }
                    .onChange(of: eventsMaxSizeMB)       { _ in syncStorageOverrides() }
                    .onChange(of: alertsRetentionDays)   { _ in syncStorageOverrides() }
                    .onChange(of: alertsMaxSizeMB)       { _ in syncStorageOverrides() }
                    .onChange(of: campaignsRetentionDays) { _ in syncStorageOverrides() }
                    .onChange(of: campaignsMaxSizeMB)    { _ in syncStorageOverrides() }
                    .onAppear { migrateLegacyStorageKeys() }
                }

                // v1.9 hot-fix: manual events.db flush. Workaround
                // for the v1.8.x size-cap regression where the
                // hourly enforcer hasn't kept up. Sends SIGUSR2 to
                // the daemon, which runs the size-cap sweep + VACUUM
                // immediately and writes a status snapshot. Surfaces
                // the current footprint and last-run timestamp.
                GroupBox(String(localized: "settings.flushTitle",
                                 defaultValue: "Manual event prune")) {
                    flushNowControls
                }

                // v1.9 hot-fix: clean removal path for the system
                // extension. Apple gates `systemextensionsctl
                // uninstall` behind SIP-disabled, so operators on
                // SIP-enabled Macs (the default) couldn't easily
                // remove a misbehaving sysext from the CLI. Calling
                // OSSystemExtensionRequest.deactivationRequest from
                // the host app is the supported alternative —
                // surfaces a system-modal approval dialog and
                // unregisters cleanly.
                GroupBox(String(localized: "settings.sysextRecoveryTitle",
                                 defaultValue: "System Extension")) {
                    sysextRecoveryControls
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
                        if notificationsOSDenied {
                            HStack(alignment: .top, spacing: 8) {
                                Image(systemName: "exclamationmark.triangle.fill")
                                    .foregroundStyle(.orange)
                                VStack(alignment: .leading, spacing: 4) {
                                    Text(String(localized: "settings.notificationsDenied",
                                                defaultValue: "Notifications are turned off for MacCrab in System Settings."))
                                        .scaledSystem(12, weight: .medium)
                                    Text(String(localized: "settings.notificationsDeniedHint",
                                                defaultValue: "MacCrab can't show alert banners until you allow notifications. Detections are still recorded and visible in the dashboard."))
                                        .scaledSystem(11)
                                        .foregroundStyle(.secondary)
                                    Button(String(localized: "settings.openNotificationSettings",
                                                  defaultValue: "Open System Settings → Notifications")) {
                                        if let url = URL(string: "x-apple.systempreferences:com.apple.Notifications-Settings.extension") {
                                            NSWorkspace.shared.open(url)
                                        }
                                    }
                                    .scaledSystem(11)
                                }
                                Spacer()
                            }
                            .padding(8)
                            .background(Color.orange.opacity(0.1))
                            .cornerRadius(6)
                        }
                        Toggle(String(localized: "settings.showNotifications", defaultValue: "Show notifications for detection alerts"), isOn: $alertNotifications)
                            // v1.11.0 (audit functionality HIGH): persist
                            // changes to ~/Library/Application Support/MacCrab/
                            // alert_notifications.json (the dashboard runs
                            // as the user, can't write the root-owned
                            // /Library/... path). The daemon's
                            // loadAlertNotificationConfig probes BOTH the
                            // system AND user-home paths and picks the
                            // most-recently-modified — see DaemonSetup
                            // for the user-home walker.
                            // v1.11.0 RC2 (audit security/stability HIGH):
                            // debounced 500ms
                            // so rapid clicks don't issue parallel SIGHUPs
                            // (each SIGHUP runs an expensive retroactive
                            // scan + storage reload).
                            .onChange(of: alertNotifications) { _ in scheduleAlertNotificationSync() }
                            .task {
                                // Reflect the OS-level authorization (banners
                                // are posted by the app via UNUserNotificationCenter).
                                let status = await UNUserNotificationCenter.current()
                                    .notificationSettings().authorizationStatus
                                notificationsOSDenied = (status == .denied)
                            }

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
                                .onChange(of: minAlertSeverity) { _ in scheduleAlertNotificationSync() }
                            }

                            Text(String(localized: "settings.severityHelp", defaultValue: "Only alerts at or above this severity will trigger a macOS notification. Daemon picks up changes on next restart or SIGHUP."))
                                .font(.caption)
                                .foregroundColor(.secondary)

                            // v1.18: warn about the noisy end of the floor.
                            // "informational"/"low" post an OS banner for nearly
                            // every detection; every alert still appears in the
                            // dashboard regardless of this floor.
                            if minAlertSeverity == "informational" || minAlertSeverity == "low" {
                                HStack(alignment: .top, spacing: 6) {
                                    Image(systemName: "exclamationmark.triangle.fill")
                                        .foregroundColor(.orange)
                                    Text(String(localized: "settings.severityNoiseWarning", defaultValue: "At this level nearly every detection posts a macOS banner. Most users want High. Every alert appears in the dashboard regardless of this setting."))
                                        .font(.caption)
                                        .foregroundColor(.orange)
                                }
                            }
                        }
                    }
                    .padding(8)
                }

                GroupBox(String(localized: "settings.agentControl", defaultValue: "Agent Control (MCP)")) {
                    VStack(alignment: .leading, spacing: 10) {
                        Text(String(localized: "settings.agentControlHelp", defaultValue: "Let a Claude/Codex agent on this Mac customise MacCrab through the MCP server. Every tier is off by default and each change is audit-logged. Turn on only what you need."))
                            .font(.caption).foregroundColor(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                        Toggle(isOn: $agentCapConfig) {
                            VStack(alignment: .leading, spacing: 1) {
                                Text(String(localized: "settings.agentTier.config", defaultValue: "Tune detection"))
                                Text(String(localized: "settings.agentTier.configDesc", defaultValue: "Built-in rule settings, reload rules, refresh intel, safe daemon tunables."))
                                    .font(.caption).foregroundColor(.secondary)
                            }
                        }
                        .onChange(of: agentCapConfig) { _ in syncAgentCapabilities() }
                        Toggle(isOn: $agentCapAuthoring) {
                            VStack(alignment: .leading, spacing: 1) {
                                Text(String(localized: "settings.agentTier.authoring", defaultValue: "Author rules"))
                                Text(String(localized: "settings.agentTier.authoringDesc", defaultValue: "Create and delete detection rules (validated by the compiler)."))
                                    .font(.caption).foregroundColor(.secondary)
                            }
                        }
                        .onChange(of: agentCapAuthoring) { _ in syncAgentCapabilities() }
                        // Enabling this tier requires an explicit confirm (it lets an
                        // agent reduce detection). The binding does NOT commit on
                        // turn-ON — it only raises the dialog — so dismissing the
                        // dialog any way (Esc, click-outside, Cancel) leaves the toggle
                        // OFF rather than stuck ON-but-never-granted. Grant commits it.
                        Toggle(isOn: Binding(
                            get: { agentCapResponse },
                            set: { wantOn in
                                if wantOn {
                                    confirmAgentResponseTier = true
                                } else {
                                    agentCapResponse = false
                                    syncAgentCapabilities()
                                }
                            }
                        )) {
                            VStack(alignment: .leading, spacing: 1) {
                                Text(String(localized: "settings.agentTier.response", defaultValue: "Change defense-affecting config"))
                                Text(String(localized: "settings.agentTier.responseDesc", defaultValue: "Toggle ES introspection / file-open subscriptions and ultrasonic. Disabling these reduces detection — grant with care."))
                                    .font(.caption).foregroundColor(.orange)
                            }
                        }
                    }
                    .padding(8)
                }
                .confirmationDialog(
                    String(localized: "settings.agentTier.confirmTitle",
                           defaultValue: "Let an AI agent change defense-affecting settings?"),
                    isPresented: $confirmAgentResponseTier, titleVisibility: .visible
                ) {
                    Button(String(localized: "settings.agentTier.confirmGrant",
                                  defaultValue: "Grant — I control this agent"), role: .destructive) {
                        agentCapResponse = true     // commit ONLY on explicit grant
                        syncAgentCapabilities()
                    }
                    Button(String(localized: "common.cancel", defaultValue: "Cancel"), role: .cancel) {
                        agentCapResponse = false   // defensive: never granted, stay OFF
                    }
                } message: {
                    Text(String(localized: "settings.agentTier.confirmBody",
                                defaultValue: "An agent granted this tier can turn OFF Endpoint Security introspection and other event capture — reducing MacCrab's detection. Every change is audit-logged. Grant only if you fully control this agent."))
                }

                GroupBox(String(localized: "settings.netEnrich", defaultValue: "Network enrichment (privacy)")) {
                    VStack(alignment: .leading, spacing: 10) {
                        Text(String(localized: "settings.netEnrichHelp", defaultValue: "MacCrab is on-device by default — none of these make any network request until you turn them on. Local detection (rules, sequences, campaigns, bundled threat-intel) is unaffected. Each lookup below reaches a public service; turn on only what you want."))
                            .font(.caption).foregroundColor(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                        Toggle(isOn: $enrichThreatIntel) {
                            VStack(alignment: .leading, spacing: 1) {
                                Text(String(localized: "settings.enrich.threatIntel", defaultValue: "Threat-intel feeds (abuse.ch)"))
                                Text(String(localized: "settings.enrich.threatIntelDesc", defaultValue: "Download IOC lists (URLhaus / MalwareBazaar / Feodo) every 4 hours. Download-only — nothing about your machine is uploaded."))
                                    .font(.caption).foregroundColor(.orange)
                            }
                        }
                        .onChange(of: enrichThreatIntel) { _ in syncEnrichmentOverrides() }
                        Toggle(isOn: $enrichVulnScan) {
                            VStack(alignment: .leading, spacing: 1) {
                                Text(String(localized: "settings.enrich.vulnScan", defaultValue: "Vulnerability scan (osv.dev)"))
                                Text(String(localized: "settings.enrich.vulnScanDesc", defaultValue: "Look up CVEs for your installed apps/packages. Sends your software inventory (anonymous, but it is your machine's software list)."))
                                    .font(.caption).foregroundColor(.orange)
                            }
                        }
                        .onChange(of: enrichVulnScan) { _ in syncEnrichmentOverrides() }
                        Toggle(isOn: $enrichPackageFreshness) {
                            VStack(alignment: .leading, spacing: 1) {
                                Text(String(localized: "settings.enrich.packageFreshness", defaultValue: "Package freshness (npm / PyPI / Homebrew / crates)"))
                                Text(String(localized: "settings.enrich.packageFreshnessDesc", defaultValue: "Check a package's age when you install one. The lookup reveals the package name you are installing."))
                                    .font(.caption).foregroundColor(.orange)
                            }
                        }
                        .onChange(of: enrichPackageFreshness) { _ in syncEnrichmentOverrides() }
                        Toggle(isOn: $enrichCertTransparency) {
                            VStack(alignment: .leading, spacing: 1) {
                                Text(String(localized: "settings.enrich.certTransparency", defaultValue: "Certificate transparency (crt.sh)"))
                                Text(String(localized: "settings.enrich.certTransparencyDesc", defaultValue: "Look up certificates for domains you connect to. The lookup reveals the domain. The local typosquat check still runs either way."))
                                    .font(.caption).foregroundColor(.orange)
                            }
                        }
                        .onChange(of: enrichCertTransparency) { _ in syncEnrichmentOverrides() }
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

    // MARK: - Forensics

    @AppStorage("forensics.catalogBaseURL") private var forensicsCatalogBaseURL: String = ""
    // v1.18: default flipped 0 (never) → 365 (1 year). Forensic scans now
    // auto-prune after a year unless the operator picks "Never". The
    // launch-time sweep (MacCrabApp.applicationDidFinishLaunching) and the
    // "Run cleanup now" button both honor this via CaseManager.pruneCases.
    @AppStorage("forensics.retentionDays") private var forensicsRetentionDays: Int = 365
    @State private var retentionDeleteResult: String? = nil
    private static let officialForensicsCatalog = "https://rave.maccrab.com/"

    private var forensicsTab: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                GroupBox(String(localized: "settings.forensicsCatalog", defaultValue: "Plugin catalog source")) {
                    VStack(alignment: .leading, spacing: 12) {
                        Text(String(localized: "settings.forensicsCatalogDesc", defaultValue: "Where the Forensics Catalog tab fetches its plugin list from. Leave blank to use the official catalog at rave.maccrab.com."))
                            .font(.caption)
                            .foregroundColor(.secondary)
                        TextField("https://rave.maccrab.com/", text: $forensicsCatalogBaseURL)
                            .textFieldStyle(.roundedBorder)
                            .scaledSystem(12, design: .monospaced)
                        HStack(spacing: 8) {
                            Button {
                                forensicsCatalogBaseURL = ""
                            } label: {
                                Text(String(localized: "settings.useOfficial", defaultValue: "Use official"))
                            }
                            .buttonStyle(.bordered)
                            .controlSize(.small)
                            Button {
                                forensicsCatalogBaseURL = "http://localhost:4321/rave/"
                            } label: {
                                Text(String(localized: "settings.useLocalhost", defaultValue: "Use localhost:4321"))
                            }
                            .buttonStyle(.bordered)
                            .controlSize(.small)
                            Spacer()
                        }
                        if !forensicsCatalogBaseURL.isEmpty &&
                            forensicsCatalogBaseURL != Self.officialForensicsCatalog {
                            HStack(alignment: .top, spacing: 6) {
                                Image(systemName: "exclamationmark.triangle.fill")
                                    .foregroundStyle(.orange)
                                    .scaledSystem(11)
                                    .padding(.top, 1)
                                Text(String(localized: "settings.nonOfficialWarn", defaultValue: "Custom catalog source set. Plugins fetched here haven't been vetted by the official rave team. The Catalog tab will show a warning banner. Use only for local development and testing."))
                                    .font(.caption)
                                    .foregroundColor(.orange)
                            }
                            .padding(.top, 4)
                        }
                        Text(String(localized: "settings.catalogReopen", defaultValue: "Reopen the Catalog tab after changing this setting."))
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }
                    .padding(8)
                }

                GroupBox(String(localized: "settings.forensicsRetention", defaultValue: "Scan retention")) {
                    VStack(alignment: .leading, spacing: 12) {
                        Text(String(localized: "settings.forensicsRetentionDesc", defaultValue: "Each scan stays on disk in ~/Library/Application Support/MacCrab/Cases/ until you delete it. Pick a retention age below 0 = never auto-delete. The cleanup runs when you click the button or the next time the dashboard opens."))
                            .font(.caption)
                            .foregroundColor(.secondary)
                        HStack(spacing: 8) {
                            Text(String(localized: "settings.retentionLabel", defaultValue: "Auto-delete scans older than:"))
                            Picker("", selection: $forensicsRetentionDays) {
                                Text("Never").tag(0)
                                Text("7 days").tag(7)
                                Text("30 days").tag(30)
                                Text("90 days").tag(90)
                                Text("180 days").tag(180)
                                Text("1 year").tag(365)
                            }
                            .labelsHidden()
                            .frame(width: 140)
                            Spacer()
                            Button {
                                runRetentionCleanup()
                            } label: {
                                Text(String(localized: "settings.runCleanup", defaultValue: "Run cleanup now"))
                            }
                            .buttonStyle(.bordered)
                            .controlSize(.small)
                            .disabled(forensicsRetentionDays == 0)
                        }
                        if let msg = retentionDeleteResult {
                            Text(msg).font(.caption).foregroundColor(.secondary)
                        }
                    }
                    .padding(8)
                }
            }
            .padding(20)
        }
    }

    /// Walk the Cases dir and delete sub-directories whose
    /// case.sqlite mtime is older than the retention cutoff.
    /// Returns a result message for the UI.
    private func runRetentionCleanup() {
        let days = forensicsRetentionDays
        guard days > 0 else { return }
        let cutoff = Date().addingTimeInterval(-Double(days) * 86_400)
        Task {
            // CaseManager.pruneCases routes through deleteCase so encrypted
            // scans release their keychain DEK and each id is UUID-validated.
            let mgr = CaseManager(casesRoot: CaseDirectoryLayout.defaultCasesRoot, dekVault: KeychainDEKVault())
            let result = await mgr.pruneCases(olderThan: cutoff)
            let bcf = ByteCountFormatter()
            bcf.countStyle = .file
            retentionDeleteResult = result.deleted.isEmpty
                ? "No scans older than \(days) days."
                : "Deleted \(result.deleted.count) scan\(result.deleted.count == 1 ? "" : "s") · freed \(bcf.string(fromByteCount: result.freedBytes))."
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
                                // A4-06: be honest that cloud redaction is
                                // best-effort heuristics, not a guarantee, and
                                // point operators at the fully-private option.
                                Text(String(localized: "settings.llmCloudPrivacy", defaultValue: "Sensitive data (usernames, private IPs, hostnames, API-key-shaped tokens) is redacted before sending. This is best-effort heuristic scrubbing, not a guarantee — novel data shapes can still slip through. For fully private analysis, use a local Ollama backend, where no data leaves this Mac."))
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
            // v1.10.2 (audit security HIGH): write atomically THEN tighten
            // perms so the API key copy never lands at 0o644 (umask
            // default). Keychain is the primary store; this file copy
            // exists for the legacy AppState.ensureLLMService read path
            // that still consumes JSON, and previously left every Claude
            // / OpenAI / Mistral / Gemini key world-readable in
            // ~/Library/Application Support/MacCrab/llm_config.json.
            try? data.write(to: URL(fileURLWithPath: configPath), options: .atomic)
            try? FileManager.default.setAttributes(
                [.posixPermissions: NSNumber(value: Int16(0o600))],
                ofItemAtPath: configPath
            )
        }

        // v1.17.4: also push the NON-SECRET config to the ROOT engine via the
        // privileged inbox. The user-dir file above is read only by the app's
        // own LLM stack; the root sysext reads /Library/.../llm_config.json,
        // which this app can't write directly — so engine-side LLM features
        // (campaign investigation, etc.) were silently dead. Keys are NOT sent
        // (the keychain is the cross-process key store); the sysext
        // URL-hardens on receipt. Takes effect on the next engine restart.
        var engineConfig: [String: Any] = [
            "enabled": llmEnabled,
            "provider": llmProvider,
            "ollama_url": llmOllamaURL,
            "ollama_model": llmOllamaModel,
        ]
        switch llmProvider {
        case "openai":
            engineConfig["openai_url"] = llmOpenAIURL
            engineConfig["openai_model"] = llmModel.isEmpty ? "gpt-4o-mini" : llmModel
        case "claude":
            engineConfig["claude_model"] = llmModel.isEmpty ? "claude-sonnet-4-6" : llmModel
        case "mistral":
            engineConfig["mistral_model"] = llmModel.isEmpty ? "mistral-small-latest" : llmModel
        case "gemini":
            engineConfig["gemini_model"] = llmModel.isEmpty ? "gemini-2.0-flash" : llmModel
        default: break
        }
        V2DaemonControl.sendLLMConfig(engineConfig)

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
        // v1.19.1: route through the merge-safe shared writer so this storage
        // block no longer clobbers the top-level network-enrichment flags that
        // share user_overrides.json, and reload via the cross-uid-safe inbox
        // path. (The old bare `pkill -HUP com.maccrab.agent` here was EPERM
        // against the root sysext + hardened-runtime-blocked, so it never
        // actually reloaded release builds — reloadDetectionRules() fixes that.)
        _ = V2DaemonControl.writeUserOverrides { obj in
            obj["storage"] = [
                "eventsHotTierMinutes":   eventsHotTierMinutes,
                "eventsMaxSizeMB":        eventsMaxSizeMB,
                "alertsRetentionDays":    alertsRetentionDays,
                "alertsMaxSizeMB":        alertsMaxSizeMB,
                "campaignsRetentionDays": campaignsRetentionDays,
                "campaignsMaxSizeMB":     campaignsMaxSizeMB,
            ]
        }
        _ = V2DaemonControl.reloadDetectionRules()
    }

    /// v1.19.1: persist the four opt-in network-enrichment flags + ask the
    /// daemon to re-read live. All four surfaces (this Settings section, the
    /// first-run prompt, the Intel card) bind the SAME enrich.* AppStorage
    /// keys and funnel through this one helper so state can't diverge.
    private func syncEnrichmentOverrides() {
        _ = V2DaemonControl.applyEnrichmentFlags(
            threatIntel: enrichThreatIntel,
            vulnScan: enrichVulnScan,
            packageFreshness: enrichPackageFreshness,
            certTransparency: enrichCertTransparency
        )
    }

    /// v1.11.0 RC2 ship-blocker fix: 500ms debounce around
    /// `syncAlertNotificationConfig`. Same shape + rationale as
    /// `scheduleWebhookSync` below — rapid Picker tab/click cycles
    /// previously fired one SIGHUP per onChange, and each SIGHUP
    /// runs the retroactive scan + storage reload + rule reload.
    /// v1.18: persist the agent-control capability grants. SECURITY: the MCP
    /// server trusts mcp_capabilities.json ONLY when it is root-owned, so the
    /// dashboard (uid 501) does NOT write it directly — it routes the human's
    /// choice through the privileged inbox and the ROOT engine writes the file.
    /// This is what makes "an agent can't grant itself a tier" hold: an agent
    /// at uid 501 can write a user-owned file, but the MCP ignores any file not
    /// owned by root.
    private func syncAgentCapabilities() {
        let payload: [String: Any] = [
            "config": agentCapConfig,
            "authoring": agentCapAuthoring,
            "response": agentCapResponse,
            "requester": "MacCrabApp",
        ]
        guard let data = try? JSONSerialization.data(withJSONObject: payload) else { return }
        let inboxDir = "/Library/Application Support/MacCrab/inbox"
        let userInboxDir = NSHomeDirectory() + "/Library/Application Support/MacCrab/inbox"
        for dir in [inboxDir, userInboxDir] {
            try? FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
            let path = "\(dir)/set-agent-capabilities-\(Int(Date().timeIntervalSince1970))-\(getpid())-\(UUID().uuidString.prefix(8)).json"
            try? data.write(to: URL(fileURLWithPath: path))
        }
    }

    private func scheduleAlertNotificationSync() {
        pendingAlertNotificationSync?.cancel()
        pendingAlertNotificationSync = Task {
            do {
                try await Task.sleep(nanoseconds: 500_000_000)
            } catch {
                return
            }
            guard !Task.isCancelled else { return }
            await MainActor.run { self.syncAlertNotificationConfig() }
        }
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

    /// v1.11.0 (audit functionality HIGH): write the OS-notification
    /// config to `<supportDir>/alert_notifications.json` and SIGHUP the
    /// daemon so `NotificationOutput.minimumSeverity` updates without
    /// a manual restart. Closes a wire-the-orphans gap — the toggle +
    /// picker existed since v1.0 but no daemon code consumed them.
    /// Schema matches `loadAlertNotificationConfig(supportDir:)` in
    /// `Sources/MacCrabAgentKit/DaemonSetup.swift`.
    private func syncAlertNotificationConfig() {
        let configDir = NSHomeDirectory() + "/Library/Application Support/MacCrab"
        try? FileManager.default.createDirectory(atPath: configDir, withIntermediateDirectories: true)
        let path = configDir + "/alert_notifications.json"
        let payload: [String: Any] = [
            "enabled": alertNotifications,
            "min_severity": minAlertSeverity,
        ]
        guard let data = try? JSONSerialization.data(
            withJSONObject: payload,
            options: [.prettyPrinted, .sortedKeys]
        ) else { return }
        let tmp = path + ".tmp"
        do {
            try data.write(to: URL(fileURLWithPath: tmp))
            _ = try? FileManager.default.removeItem(atPath: path)
            try FileManager.default.moveItem(atPath: tmp, toPath: path)
        } catch { return }
        // SIGHUP the sysext so the new config takes effect on the next
        // notification. Best-effort — same pattern as syncWebhookConfig.
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/pkill")
        task.arguments = ["-HUP", "com.maccrab.agent"]
        task.standardOutput = Pipe()
        task.standardError = Pipe()
        try? task.run()
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
                    .scaledSystem(64)

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
                    Text(String(localized: "settings.aboutStats", defaultValue: "17 event sources | 5 detection layers | 485 detection rules"))
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
    /// v1.9 hot-fix: manual events.db prune button + status. Sends
    /// SIGUSR2 to the daemon (which runs the size-cap enforcer +
    /// VACUUM and writes a status snapshot). Refreshes the snapshot
    /// on appear so the values are current when the user opens the
    /// pane. Auto-refreshes every 2 s while a flush is in flight so
    /// the operator gets live feedback as the daemon works.
    @ViewBuilder
    private var flushNowControls: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(alignment: .firstTextBaseline) {
                VStack(alignment: .leading, spacing: 2) {
                    Text(String(localized: "settings.flushBody",
                                 defaultValue: "Run the events.db size-cap sweep + VACUUM right now. Useful when the file has grown well past the configured cap (recovery from the v1.8.x size-cap regression)."))
                        .font(.callout)
                        .foregroundStyle(.secondary)
                    HStack(spacing: 12) {
                        // Use the same path-resolution as the storage
                        // rows above (mtime-newer wins) so this number
                        // and "Events" row's "Current" stay consistent.
                        Text(String(localized: "settings.flushCurrentSize",
                                     defaultValue: "Current size: \(currentSize(databaseFile: "events.db"))"))
                            .font(.caption)
                        Text(String(localized: "settings.flushPath",
                                     defaultValue: "(\((databasePathForFile("events.db") as NSString).deletingLastPathComponent))"))
                            .font(.caption2)
                            .foregroundStyle(.tertiary)
                            .lineLimit(1)
                            .truncationMode(.middle)
                        if let last = appState.storageFlushStatus?.lastRunAt {
                            Text(String(localized: "settings.flushLastRun",
                                         defaultValue: "Last run \(last.formatted(.relative(presentation: .numeric)))"))
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        } else {
                            // v1.9.0 (audit UX-M7): explicit empty
                            // state. Pre-fix the row was just blank
                            // on first install, leaving the user with
                            // no signal whether the feature had ever
                            // been exercised.
                            Text(String(localized: "settings.flushLastRunNever",
                                         defaultValue: "Last run: never"))
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    }
                    if let status = appState.storageFlushStatus,
                       status.bytesBefore > 0 {
                        let before = ByteCountFormatter.string(
                            fromByteCount: Int64(status.bytesBefore), countStyle: .file)
                        let after = ByteCountFormatter.string(
                            fromByteCount: Int64(status.bytesAfter), countStyle: .file)
                        Text(String(localized: "settings.flushDelta",
                                     defaultValue: "Last sweep: \(before) → \(after)"))
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                    }
                }
                Spacer()
                Button {
                    appState.requestStorageFlush()
                } label: {
                    if appState.storageFlushInFlight {
                        HStack(spacing: 6) {
                            ProgressView().controlSize(.small)
                            Text(String(localized: "settings.flushRunning",
                                         defaultValue: "Reducing…"))
                        }
                    } else {
                        Label(
                            String(localized: "settings.flushButton",
                                    defaultValue: "Reduce events.db now"),
                            systemImage: "trash.slash"
                        )
                    }
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.regular)
                .disabled(appState.storageFlushInFlight)
            }
        }
        .padding(8)
        .task { appState.refreshStorageFlushStatus() }
        // While a flush is in flight, poll the snapshot every 2 s so
        // the UI shows the daemon's response as soon as it lands.
        .onChange(of: appState.storageFlushInFlight) { inFlight in
            guard inFlight else { return }
            Task {
                while await MainActor.run(body: { appState.storageFlushInFlight }) {
                    try? await Task.sleep(nanoseconds: 2_000_000_000)
                    await MainActor.run { appState.refreshStorageFlushStatus() }
                }
            }
        }
    }

    /// v1.9 hot-fix: sysext deactivate button + status. Submits an
    /// OSSystemExtensionRequest.deactivationRequest via the existing
    /// SystemExtensionManager. macOS shows a system-modal approval
    /// dialog. State binds the button label so the user gets clear
    /// feedback through the activate→approve→deactivate cycle.
    @ViewBuilder
    private var sysextRecoveryControls: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(String(localized: "settings.sysextBody",
                         defaultValue: "Remove the installed Endpoint Security extension. Use when an older version is causing issues (size-cap regression, repeated crashes, sysext zombies). System Settings will prompt for approval; on success the extension is unregistered and won't respawn."))
                .font(.callout)
                .foregroundStyle(.secondary)
            HStack(spacing: 12) {
                statusBadge
                Spacer()
                Button {
                    // v1.9.0 (audit UX-H6): in-app confirmation
                    // dialog. macOS will also show its own system
                    // modal AFTER the request submits, but a misclick
                    // can already kick off the OS flow without a
                    // recoverable dashboard signal — the operator
                    // explicitly acks the destructive action here
                    // first.
                    sysextRemoveConfirmShown = true
                } label: {
                    Label(
                        String(localized: "settings.sysextDeactivate",
                                defaultValue: "Remove System Extension"),
                        systemImage: "trash"
                    )
                }
                .buttonStyle(.bordered)
                .controlSize(.regular)
                .disabled(sysextManager.state == .activating)
                .confirmationDialog(
                    String(localized: "settings.sysextRemoveTitle",
                            defaultValue: "Remove the MacCrab Endpoint Security extension?"),
                    isPresented: $sysextRemoveConfirmShown,
                    titleVisibility: .visible
                ) {
                    Button(
                        String(localized: "settings.sysextRemoveConfirm",
                                defaultValue: "Remove"),
                        role: .destructive
                    ) {
                        sysextManager.deactivate()
                    }
                    Button(
                        String(localized: "settings.sysextRemoveCancel",
                                defaultValue: "Cancel"),
                        role: .cancel
                    ) { }
                } message: {
                    Text(String(
                        localized: "settings.sysextRemoveBody",
                        defaultValue: "Detection coverage will stop until you re-install. macOS will show its own approval dialog after this; cancel there if you change your mind."
                    ))
                }
            }
        }
        .padding(8)
    }

    private var statusBadge: some View {
        let (label, color, fullDetail) = sysextStatusLabelAndColor()
        return HStack(spacing: 4) {
            Circle().fill(color).frame(width: 8, height: 8)
            Text(label).font(.caption).lineLimit(1).truncationMode(.tail)
        }
        .padding(.horizontal, 8).padding(.vertical, 4)
        .background(Capsule().fill(color.opacity(0.1)))
        // v1.9.0 (audit UX-H6): hover help carrying the full state
        // detail so the truncated `Failed: O...` label stops being
        // a dead end. `fullDetail` falls back to `label` when the
        // state has nothing extra to show — the help is still
        // useful as a tooltip on narrow sidebars.
        .help(fullDetail ?? label)
    }

    private func sysextStatusLabelAndColor() -> (String, Color, String?) {
        switch sysextManager.state {
        case .unknown:
            return (String(localized: "settings.sysextStateUnknown", defaultValue: "Status unknown"), .secondary, nil)
        case .notActivated:
            return (String(localized: "settings.sysextStateNotInstalled", defaultValue: "Not installed"), .secondary, nil)
        case .activating:
            return (String(localized: "settings.sysextStateActivating", defaultValue: "Working…"), .orange, nil)
        case .awaitingApproval:
            return (String(localized: "settings.sysextStateNeedsApproval", defaultValue: "Awaiting approval"), .orange, nil)
        case .activated:
            return (String(localized: "settings.sysextStateActive", defaultValue: "Active"), .green, nil)
        case .failed(let msg):
            return (
                String(localized: "settings.sysextStateFailed", defaultValue: "Failed: \(msg)"),
                .red,
                String(localized: "settings.sysextStateFailedDetail",
                        defaultValue: "Failed: \(msg)")
            )
        }
    }

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

        if let legacyRetention = defaults.object(forKey: "retentionDays") as? Int {
            if alertsRetentionDays == 365 && campaignsRetentionDays == 365 {
                alertsRetentionDays    = max(30, min(legacyRetention, 1095))
                campaignsRetentionDays = max(30, min(legacyRetention, 1095))
            }
        }

        if let legacyCap = defaults.object(forKey: "maxDatabaseSizeMB") as? Int {
            if eventsMaxSizeMB == 200 {
                eventsMaxSizeMB = max(100, min(legacyCap, 2000))
            }
        }

        // v1.8.0-rc4 → rc5: eventsHotTierHours folded onto
        // eventsHotTierMinutes (× 60). Apply once on first appear so a
        // user who set the slider during rc-testing doesn't lose their
        // choice.
        if let legacyHours = defaults.object(forKey: "storage.eventsHotTierHours") as? Int {
            if eventsHotTierMinutes == 30 {
                eventsHotTierMinutes = max(15, min(legacyHours * 60, 1440))
            }
        }

        // Push the (possibly migrated) values to user_overrides.json so
        // the daemon's overlay reader sees them on the next SIGHUP / boot.
        syncStorageOverrides()
    }

    /// Format the events hot-tier as "30m" / "2h" / "24h" depending on
    /// magnitude. Pure UX cosmetic — the underlying value is always
    /// minutes.
    private func eventsTierLabel(_ minutes: Int) -> String {
        if minutes < 60 { return "\(minutes)m" }
        if minutes % 60 == 0 { return "\(minutes / 60)h" }
        return "\(minutes / 60)h \(minutes % 60)m"
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
