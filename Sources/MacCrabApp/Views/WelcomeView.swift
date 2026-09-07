// WelcomeView.swift
// MacCrabApp
//
// First-run welcome screen with language selection and quick setup.

import SwiftUI

/// Maps the user's system language onto one of the 14 identifiers we actually
/// ship. Both of the obvious approaches are wrong, in opposite directions:
/// `Locale.current.language.languageCode` drops the script/region subtag, so
/// "zh-Hant-TW" collapses to "zh"; the `AppleLanguages` entries SettingsView
/// reads keep too much, so "en-IE" never equals "en". Neither matches a row in
/// the pickers, which key on the shipped identifiers ("zh-Hans", "zh-Hant",
/// "pt-BR") — so Chinese and Brazilian users got no preselected row, and the
/// bare "zh" that was then written back to AppleLanguages resolved to
/// SIMPLIFIED, silently downgrading a Traditional-Chinese user to a different
/// written language. Bundle's own matcher keeps the script subtag and can only
/// return an identifier we ship.
enum ShippedLocale {
    /// The localizations present in the running bundle. Empty under a plain
    /// `swift run` — SPM keeps the .lproj inside Bundle.module and only
    /// scripts/build-release.sh copies them to Contents/Resources — which is
    /// why `resolve` returns nil there instead of asserting "en", leaving the
    /// callers free to keep their old dev-time behaviour.
    static var available: [String] {
        Bundle.main.localizations.filter { $0 != "Base" }
    }

    /// Resolve `preferred` (a possibly region-tagged identifier, or nil to use
    /// the system's preference order) to a shipped identifier, or nil if the
    /// bundle carries no localizations at all.
    static func resolve(preferring preferred: String? = nil) -> String? {
        let shipped = available
        guard !shipped.isEmpty else { return nil }
        return Bundle.preferredLocalizations(
            from: shipped, forPreferences: preferred.map { [$0] }).first
    }
}

struct WelcomeView: View {
    @Binding var isPresented: Bool
    @ObservedObject var sysextManager: SystemExtensionManager
    var engineSource: V2EngineSource = .session
    @Environment(\.scenePhase) private var scenePhase
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    // See ShippedLocale above: truncating to the bare ISO-639 code left
    // zh-Hans / zh-Hant / pt-BR users with no preselected row, and turned a
    // Traditional-Chinese system into a Simplified-Chinese app at :422.
    @State private var selectedLanguage: String =
        ShippedLocale.resolve() ?? Locale.current.language.languageCode?.identifier ?? "en"
    @State private var currentStep = 0
    // v1.21.5: first-run installs pick a dashboard mode here (default
    // Basic). Written to UIMode.storageKey only on wizard completion —
    // upgrades never see the wizard and keep the .advanced fallback.
    @State private var selectedUIMode: UIMode = .basic

    // MARK: - Daemon Health State
    @State private var engineReady = false
    @State private var compiledRuleCount = 0
    // v1.21.5: live FDA probe result (was a static instruction row).
    @State private var fdaStatus: FullDiskAccessStatus = .unknown
    @State private var isChecking = false

    private let languages: [(code: String, name: String, native: String)] = [
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

    var body: some View {
        VStack(spacing: 0) {
            // Step indicator
            HStack(spacing: 8) {
                ForEach(0..<3, id: \.self) { step in
                    Circle()
                        .fill(step <= currentStep ? Color.accentColor : Color.secondary.opacity(0.3))
                        .frame(width: 8, height: 8)
                }
            }
            .padding(.top, 20)

            .accessibilityElement(children: .ignore)
            .accessibilityLabel(String(localized: "welcome.step", defaultValue: "Step \(currentStep + 1) of 3"))

            ScrollView {
                Group {
                    switch currentStep {
                    case 0: languageStep
                    case 1: welcomeStep
                    case 2: readyStep
                    default: EmptyView()
                    }
                }
                .frame(maxWidth: .infinity)
                .padding(.vertical, 20)
            }
            .id(currentStep)

            // Navigation
            HStack {
                if currentStep > 0 {
                    Button(String(localized: "ui.RuleWizard.back", defaultValue: "Back")) {
                        withAnimation(reduceMotion ? nil : .easeInOut(duration: 0.18)) { currentStep -= 1 }
                    }
                    .controlSize(.large)
                }

                Spacer()

                if currentStep < 2 {
                    Button(String(localized: "ui.RuleWizard.next", defaultValue: "Next")) {
                        withAnimation(reduceMotion ? nil : .easeInOut(duration: 0.18)) { currentStep += 1 }
                    }
                    .buttonStyle(.borderedProminent)
                    .controlSize(.large)
                    .keyboardShortcut(.defaultAction)
                } else {
                    // Step 3: one-click Enable Protection. Kicking off the
                    // sysext activation request here means the user only
                    // needs to make one decision (approve in System
                    // Settings) instead of two (dismiss wizard → click
                    // Enable Protection on Overview → approve). When the
                    // sysext is already active we fall back to the
                    // original Get Started behavior.
                    Button(sysextManager.state == .activated
                        ? String(localized: "welcome.getStarted", defaultValue: "Get Started")
                        : String(localized: "welcome.enableProtection", defaultValue: "Enable Protection")
                    ) {
                        applySetup()
                        if sysextManager.state != .activated {
                            sysextManager.activate()
                        }
                        isPresented = false
                    }
                    .buttonStyle(.borderedProminent)
                    .controlSize(.large)
                    .keyboardShortcut(.defaultAction)
                }
            }
            .padding(20)
        }
        .frame(minWidth: 500, idealWidth: 560, maxWidth: 700,
               minHeight: 400, idealHeight: 600, maxHeight: 800)
        .task(id: currentStep) {
            guard currentStep == 2 else { return }
            while !Task.isCancelled {
                if scenePhase == .active { await checkDaemonHealth() }
                do { try await Task.sleep(for: .seconds(5)) }
                catch { return }
            }
        }
        .onChange(of: scenePhase) { phase in
            if phase == .active && currentStep == 2 { Task { await checkDaemonHealth() } }
        }
        .onChange(of: sysextManager.state) { _ in
            if currentStep == 2 { Task { await checkDaemonHealth() } }
        }
    }

    // MARK: - Step 1: Language

    private var languageStep: some View {
        VStack(spacing: 16) {
            Text("🦀")
                .scaledSystem(48)

            Text(String(localized: "welcome.title", defaultValue: "Welcome to MacCrab"))
                .font(.title).fontWeight(.bold)

            Text(String(localized: "welcome.chooseLanguage", defaultValue: "Choose your language"))
                .font(.headline)
                .foregroundColor(.secondary)

            List(languages, id: \.code, selection: $selectedLanguage) { lang in
                HStack {
                    Text(lang.native)
                        .font(.callout).fontWeight(.medium)
                    Spacer()
                    Text(lang.name)
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
                .tag(lang.code)
                .contentShape(Rectangle())
            }
            .listStyle(.bordered)
            .frame(height: 240)
        }
        .padding(.horizontal, 20)
    }

    // MARK: - Step 2: What is MacCrab

    private var welcomeStep: some View {
        VStack(spacing: 16) {
            Text("🦀")
                .scaledSystem(48)

            Text(String(localized: "welcome.whatIs", defaultValue: "What is MacCrab?"))
                .font(.title2).fontWeight(.bold)

            VStack(alignment: .leading, spacing: 12) {
                FeatureRow(icon: "shield.checkered",
                    title: String(localized: "welcome.feature.detection", defaultValue: "Real-Time Detection"),
                    description: String(localized: "welcome.feature.detectionDesc", defaultValue: "Hundreds of detection rules monitor your Mac for threats in real time"))
                FeatureRow(icon: "brain",
                    title: String(localized: "welcome.feature.ai", defaultValue: "AI Safety"),
                    description: String(localized: "welcome.feature.aiDesc", defaultValue: "Monitors AI coding tools like Claude, Cursor, and Copilot for credential access"))
                // v1.21.5: honest copy — ES is notify-only and the
                // prevention modules default off, so this row must not
                // promise inline blocking (see TCCRevocation.swift's
                // "do not describe this as an active prevention" rule).
                FeatureRow(icon: "hand.raised",
                    title: String(localized: "welcome.feature.prevention", defaultValue: "Automated Response"),
                    description: String(localized: "welcome.feature.preventionDesc", defaultValue: "Optional modules sinkhole malicious domains, block bad IPs, lock persistence locations, and can kill or quarantine on high-severity alerts \u{2014} response follows detection"))
                FeatureRow(icon: "lock.shield",
                    title: String(localized: "welcome.feature.privacy", defaultValue: "Private by default"),
                    description: String(localized: "welcome.feature.privacyDesc", defaultValue: "Runs on-device by default \u{2014} nothing leaves your Mac unless you turn on optional enrichment"))
            }
            .padding(.horizontal, 20)

            // v1.21.5: dashboard-mode picker for new installs. Default
            // Basic; persisted by applySetup() on completion only, so
            // upgrades (which never see this wizard) keep Advanced.
            VStack(alignment: .leading, spacing: 6) {
                Text(String(localized: "welcome.mode.title", defaultValue: "Choose your experience"))
                    .font(.headline)
                Picker("", selection: $selectedUIMode) {
                    ForEach(UIMode.allCases, id: \.self) { mode in
                        Text(modeLabel(mode)).tag(mode)
                    }
                }
                .pickerStyle(.segmented)
                .labelsHidden()
                Text(modeDescription(selectedUIMode))
                    .font(.caption)
                    .foregroundColor(.secondary)
                Text(String(localized: "welcome.mode.changeLater", defaultValue: "You can change this anytime in Settings"))
                    .font(.caption2)
                    .foregroundColor(.secondary)
            }
            .padding(.horizontal, 20)
        }
        .padding(.horizontal, 20)
    }

    /// v1.21.5: localized segment labels for the mode picker. The wizard
    /// rendered UIMode.displayName — English in all 14 locales while the
    /// per-mode descriptions below translated. Localized here, not on
    /// UIMode.displayName itself (SettingsView renders that elsewhere).
    private func modeLabel(_ mode: UIMode) -> String {
        switch mode {
        case .basic:
            return String(localized: "welcome.mode.basic", defaultValue: "Basic")
        case .standard:
            return String(localized: "welcome.mode.standard", defaultValue: "Standard")
        case .advanced:
            return String(localized: "welcome.mode.advanced", defaultValue: "Advanced")
        }
    }

    private func modeDescription(_ mode: UIMode) -> String {
        switch mode {
        case .basic:
            return String(localized: "welcome.mode.basicDesc", defaultValue: "The essentials \u{2014} alerts and system status")
        case .standard:
            return String(localized: "welcome.mode.standardDesc", defaultValue: "Adds events, investigation, and prevention controls")
        case .advanced:
            return String(localized: "welcome.mode.advancedDesc", defaultValue: "Every workspace, including forensics and intelligence")
        }
    }

    // MARK: - Step 3: Ready

    private var readyStep: some View {
        VStack(spacing: 16) {
            Text("🦀")
                .scaledSystem(48)

            Text(String(localized: "welcome.allSet", defaultValue: "Setup Checklist"))
                .font(.title2).fontWeight(.bold)

            // v1.21.5: only claim "ready" when the checklist is actually
            // green — the old copy said it unconditionally.
            Text(checklistComplete
                ? String(localized: "welcome.ready", defaultValue: "MacCrab is ready to protect your Mac.")
                : String(localized: "welcome.almostReady", defaultValue: "Almost there \u{2014} finish the items below to activate protection."))
                .font(.callout)
                .foregroundColor(.secondary)

            VStack(alignment: .leading, spacing: 8) {
                // Dynamic: current engine readiness
                SetupRow(
                    icon: engineReady ? "checkmark.circle.fill" : "exclamationmark.triangle.fill",
                    color: engineReady ? .green : .orange,
                    text: engineReady
                        ? String(localized: "welcome.setup.engineActive", defaultValue: "Detection engine active")
                        : String(localized: "welcome.setup.engineNotReady", defaultValue: "Protection is not ready yet — review System Extension status and permissions"))

                // Dynamic: compiled rule count. v1.21.5: the fallback lost
                // its "run make compile-rules" dev jargon — the root System
                // Extension self-heals from its signed corpus at boot.
                SetupRow(
                    icon: compiledRuleCount > 0 ? "checkmark.circle.fill" : "exclamationmark.triangle.fill",
                    color: compiledRuleCount > 0 ? .green : .orange,
                    text: compiledRuleCount > 0
                        ? "\(compiledRuleCount) detection rules loaded"
                        : String(localized: "welcome.setup.noRules", defaultValue: "Detection rules will install automatically \u{2014} restart MacCrab if this doesn't clear"))

                // Language is always set
                SetupRow(icon: "checkmark.circle.fill", color: .green,
                    text: "Language: \(languages.first { $0.code == selectedLanguage }?.native ?? "English")")

                // Dynamic: the APP's Full Disk Access (v1.21.5, was a
                // static instruction). The engine self-probes its own FDA
                // post-install and surfaces it in the System workspace.
                // Unknown remains unverified; it is not affirmative access.
                SetupRow(
                    icon: fdaStatus == .granted ? "checkmark.circle.fill" : "exclamationmark.shield",
                    color: fdaStatus == .granted ? .green : .orange,
                    text: fdaStatus == .denied
                        ? String(localized: "welcome.setup.fda", defaultValue: "Grant Full Disk Access: System Settings \u{2192} Privacy & Security \u{2192} Full Disk Access \u{2192} add MacCrab.app")
                        : (fdaStatus == .granted
                            ? String(localized: "welcome.setup.fdaGranted", defaultValue: "Full Disk Access granted")
                            : String(localized: "welcome.setup.fdaUnknown", defaultValue: "Full Disk Access has not been verified — check again after granting access")))

                // Dynamic: System Extension state (v1.21.5, was a static
                // instruction). Live via @ObservedObject — approval in
                // System Settings flips this row without Check Again.
                SetupRow(icon: sysextRow.icon, color: sysextRow.color, text: sysextRow.text)

                // UX-04: the wizard defaults to Basic (selectedUIMode = .basic)
                // and Basic HIDES the Prevention workspace
                // (V2Workspace.prevention.minimumMode == .standard) — so this row
                // handed a new user a task and the next screen removed the place
                // to do it. When Prevention won't be in their sidebar, point at
                // the mode switch instead of a tab they can't see.
                SetupRow(icon: "info.circle", color: .blue,
                    text: V2Workspace.prevention.isVisible(in: selectedUIMode)
                        ? String(localized: "welcome.setup.prevention", defaultValue: "Enable prevention in the Prevention tab")
                        : String(localized: "welcome.setup.preventionHidden", defaultValue: "Prevention controls live in the Prevention workspace — choose Standard above (or Settings → Appearance) to show it"))
            }
            .padding(16)
            .background(Color(nsColor: .controlBackgroundColor))
            .cornerRadius(12)
            .padding(.horizontal, 20)

            // Refresh button
            Button(action: {
                Task { await checkDaemonHealth() }
            }) {
                HStack(spacing: 6) {
                    Image(systemName: "arrow.clockwise")
                        .rotationEffect(.degrees(isChecking && !reduceMotion ? 360 : 0))
                        .animation(reduceMotion ? nil : (isChecking ? .linear(duration: 0.6).repeatForever(autoreverses: false) : .default), value: isChecking)
                    Text(String(localized: "welcome.setup.checkAgain", defaultValue: "Check Again"))
                }
            }
            .controlSize(.small)
            .disabled(isChecking)
        }
        .padding(.horizontal, 20)

    }

    /// v1.21.5: all live checklist rows green?
    private var checklistComplete: Bool {
        WelcomeChecklist.isComplete(
            engineReady: engineReady,
            ruleCount: compiledRuleCount,
            fda: fdaStatus,
            sysext: sysextManager.state)
    }

    /// v1.21.5: live System Extension row content.
    private var sysextRow: (icon: String, color: Color, text: String) {
        switch sysextManager.state {
        case .activated:
            return ("checkmark.circle.fill", .green,
                String(localized: "welcome.setup.esActive", defaultValue: "System Extension active"))
        case .awaitingApproval:
            return ("exclamationmark.shield", .orange,
                String(localized: "welcome.setup.esAwaiting", defaultValue: "System Extension awaiting approval \u{2014} open System Settings \u{2192} General \u{2192} Login Items & Extensions"))
        case .failed:
            return ("exclamationmark.triangle.fill", .orange,
                String(localized: "welcome.setup.esFailed", defaultValue: "System Extension activation failed \u{2014} click Enable Protection to retry"))
        case .unknown, .notActivated, .activating:
            return ("info.circle", .blue,
                String(localized: "welcome.setup.esPending", defaultValue: "System Extension: click Enable Protection below to install"))
        }
    }

    // MARK: - Daemon Health Check

    /// A retained database/WAL is history, not evidence of a live detector.
    /// Use the same current-boot heartbeat contract as System health.
    private func checkDaemonHealth() async {
        guard !isChecking else { return }
        isChecking = true
        defer { isChecking = false }
        let source = engineSource
        let result = await Task.detached(priority: .utility) {
            WelcomeHealthSnapshot(heartbeat: source.heartbeat(), fda: PermissionsProbe.fullDiskAccess())
        }.value
        guard !Task.isCancelled else { return }
        fdaStatus = result.fda
        engineReady = result.engineReady
        compiledRuleCount = result.rulesLoaded
    }

    // MARK: - Apply

    /// v1.21.5: applies language + dashboard mode and marks setup
    /// complete. This is the wizard's only completion path (an Esc
    /// dismiss leaves hasCompletedSetup false, so the wizard returns) —
    /// keeping the UIMode write here guarantees every completed
    /// first-run has an explicit mode choice.
    private func applySetup() {
        UserDefaults.standard.set([selectedLanguage], forKey: "AppleLanguages")
        UserDefaults.standard.set(selectedUIMode.rawValue, forKey: UIMode.storageKey)
        UserDefaults.standard.set(true, forKey: "hasCompletedSetup")
        UserDefaults.standard.synchronize()
        if let bundleId = Bundle.main.bundleIdentifier {
            UserDefaults(suiteName: bundleId)?.set([selectedLanguage], forKey: "AppleLanguages")
            UserDefaults(suiteName: bundleId)?.synchronize()
        }
    }
}

// MARK: - Checklist Predicate

/// Readiness copy requires affirmative evidence; the user may still finish
/// onboarding and grant permissions afterward.
struct WelcomeHealthSnapshot: Equatable, Sendable {
    let engineReady: Bool
    let rulesLoaded: Int
    let fda: FullDiskAccessStatus

    init(heartbeat: V2HeartbeatSnapshot?, fda: FullDiskAccessStatus) {
        engineReady = WelcomeChecklist.engineReady(heartbeat)
        rulesLoaded = heartbeat?.isStale == false ? heartbeat?.rulesLoaded ?? 0 : 0
        self.fda = fda
    }
}

enum WelcomeChecklist {
    static func engineReady(_ heartbeat: V2HeartbeatSnapshot?) -> Bool {
        guard let heartbeat, !heartbeat.isStale, heartbeat.isReady else { return false }
        return V2CollectorSummary(states: heartbeat.collectors.map(\.resolvedState)).allEnabledHealthy
    }

    static func isComplete(engineReady: Bool, ruleCount: Int,
                           fda: FullDiskAccessStatus,
                           sysext: SystemExtensionState) -> Bool {
        engineReady && ruleCount > 0 && fda == .granted && sysext == .activated
    }
}

// MARK: - Supporting Views

private struct FeatureRow: View {
    let icon: String
    let title: String
    let description: String

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: icon)
                .font(.title3)
                .foregroundColor(.accentColor)
                .frame(width: 24)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 2) {
                Text(title).font(.callout).fontWeight(.medium)
                Text(description).font(.caption).foregroundColor(.secondary)
            }
        }
    }
}

private struct SetupRow: View {
    let icon: String
    let color: Color
    let text: String

    var body: some View {
        HStack(spacing: 8) {
            Image(systemName: icon)
                .foregroundColor(color)
                .font(.caption)
                .accessibilityHidden(true)
            Text(text)
                .font(.callout)
        }
    }
}
