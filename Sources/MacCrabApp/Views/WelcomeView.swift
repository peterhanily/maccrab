// WelcomeView.swift
// MacCrabApp
//
// First-run welcome screen with language selection and quick setup.

import SwiftUI

struct WelcomeView: View {
    @Binding var isPresented: Bool
    @State private var selectedLanguage: String = Locale.current.language.languageCode?.identifier ?? "en"
    @State private var currentStep = 0

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

            Spacer()

            switch currentStep {
            case 0:
                languageStep
            case 1:
                welcomeStep
            case 2:
                readyStep
            default:
                EmptyView()
            }

            Spacer()

            // Navigation
            HStack {
                if currentStep > 0 {
                    Button("Back") {
                        withAnimation { currentStep -= 1 }
                    }
                    .controlSize(.large)
                }

                Spacer()

                if currentStep < 2 {
                    Button("Next") {
                        withAnimation { currentStep += 1 }
                    }
                    .buttonStyle(.borderedProminent)
                    .controlSize(.large)
                } else {
                    Button("Get Started") {
                        applyLanguage()
                        isPresented = false
                    }
                    .buttonStyle(.borderedProminent)
                    .controlSize(.large)
                }
            }
            .padding(20)
        }
        .frame(width: 500, height: 420)
    }

    // MARK: - Step 1: Language

    private var languageStep: some View {
        VStack(spacing: 16) {
            Text("🦀")
                .font(.system(size: 48))

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
                .font(.system(size: 48))

            Text(String(localized: "welcome.whatIs", defaultValue: "What is MacCrab?"))
                .font(.title2).fontWeight(.bold)

            VStack(alignment: .leading, spacing: 12) {
                FeatureRow(icon: "shield.checkered",
                    title: String(localized: "welcome.feature.detection", defaultValue: "Real-Time Detection"),
                    description: String(localized: "welcome.feature.detectionDesc", defaultValue: "348 detection rules monitor your Mac for threats in real time"))
                FeatureRow(icon: "brain",
                    title: String(localized: "welcome.feature.ai", defaultValue: "AI Safety"),
                    description: String(localized: "welcome.feature.aiDesc", defaultValue: "Monitors AI coding tools like Claude, Cursor, and Copilot for credential access"))
                FeatureRow(icon: "hand.raised",
                    title: String(localized: "welcome.feature.prevention", defaultValue: "Active Prevention"),
                    description: String(localized: "welcome.feature.preventionDesc", defaultValue: "Blocks malicious domains, quarantines files, and gates supply chain attacks"))
                FeatureRow(icon: "lock.shield",
                    title: String(localized: "welcome.feature.privacy", defaultValue: "Privacy First"),
                    description: String(localized: "welcome.feature.privacyDesc", defaultValue: "Everything runs locally \u{2014} no data ever leaves your machine"))
            }
            .padding(.horizontal, 20)
        }
        .padding(.horizontal, 20)
    }

    // MARK: - Step 3: Ready

    private var readyStep: some View {
        VStack(spacing: 16) {
            Text("🦀")
                .font(.system(size: 48))

            Text(String(localized: "welcome.allSet", defaultValue: "You\u{2019}re All Set!"))
                .font(.title2).fontWeight(.bold)

            Text(String(localized: "welcome.ready", defaultValue: "MacCrab is ready to protect your Mac."))
                .font(.callout)
                .foregroundColor(.secondary)

            VStack(alignment: .leading, spacing: 8) {
                SetupRow(icon: "checkmark.circle.fill", color: .green,
                    text: String(localized: "welcome.setup.engineActive", defaultValue: "Detection engine active"))
                SetupRow(icon: "checkmark.circle.fill", color: .green,
                    text: String(localized: "welcome.setup.rulesLoaded", defaultValue: "348 detection rules loaded"))
                SetupRow(icon: "checkmark.circle.fill", color: .green,
                    text: "Language: \(languages.first { $0.code == selectedLanguage }?.native ?? "English")")
                SetupRow(icon: "exclamationmark.shield", color: .orange,
                    text: String(localized: "welcome.setup.fda", defaultValue: "Grant Full Disk Access: System Settings \u{2192} Privacy & Security \u{2192} Full Disk Access \u{2192} add maccrabd"))
                SetupRow(icon: "exclamationmark.shield", color: .orange,
                    text: String(localized: "welcome.setup.es", defaultValue: "Endpoint Security: approve the system extension prompt on first daemon launch"))
                SetupRow(icon: "info.circle", color: .blue,
                    text: String(localized: "overview.startDaemon", defaultValue: "Start the daemon: sudo maccrabd"))
                SetupRow(icon: "info.circle", color: .blue,
                    text: String(localized: "welcome.setup.prevention", defaultValue: "Enable prevention in the Prevention tab"))
            }
            .padding(16)
            .background(Color(nsColor: .controlBackgroundColor))
            .cornerRadius(12)
            .padding(.horizontal, 20)
        }
        .padding(.horizontal, 20)
    }

    // MARK: - Apply

    private func applyLanguage() {
        UserDefaults.standard.set([selectedLanguage], forKey: "AppleLanguages")
        UserDefaults.standard.set(true, forKey: "hasCompletedSetup")
        UserDefaults.standard.synchronize()
        if let bundleId = Bundle.main.bundleIdentifier {
            UserDefaults(suiteName: bundleId)?.set([selectedLanguage], forKey: "AppleLanguages")
            UserDefaults(suiteName: bundleId)?.synchronize()
        }
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
