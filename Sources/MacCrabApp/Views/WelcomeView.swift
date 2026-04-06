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

            Text("Welcome to MacCrab")
                .font(.title).fontWeight(.bold)

            Text("Choose your language")
                .font(.headline)
                .foregroundColor(.secondary)

            ScrollView {
                LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible())], spacing: 8) {
                    ForEach(languages, id: \.code) { lang in
                        Button {
                            selectedLanguage = lang.code
                        } label: {
                            HStack {
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(lang.native)
                                        .font(.callout).fontWeight(.medium)
                                    Text(lang.name)
                                        .font(.caption2)
                                        .foregroundColor(.secondary)
                                }
                                Spacer()
                                if selectedLanguage == lang.code {
                                    Image(systemName: "checkmark.circle.fill")
                                        .foregroundColor(.accentColor)
                                }
                            }
                            .padding(8)
                            .background(selectedLanguage == lang.code ? Color.accentColor.opacity(0.1) : Color.clear)
                            .cornerRadius(8)
                            .overlay(
                                RoundedRectangle(cornerRadius: 8)
                                    .stroke(selectedLanguage == lang.code ? Color.accentColor : Color.secondary.opacity(0.2), lineWidth: 1)
                            )
                        }
                        .buttonStyle(.plain)
                    }
                }
                .padding(.horizontal)
            }
            .frame(height: 220)
        }
        .padding(.horizontal, 20)
    }

    // MARK: - Step 2: What is MacCrab

    private var welcomeStep: some View {
        VStack(spacing: 16) {
            Text("🦀")
                .font(.system(size: 48))

            Text("What is MacCrab?")
                .font(.title2).fontWeight(.bold)

            VStack(alignment: .leading, spacing: 12) {
                FeatureRow(icon: "shield.checkered", title: "Real-Time Detection", description: "273 detection rules monitor your Mac for threats in real time")
                FeatureRow(icon: "brain", title: "AI Safety", description: "Monitors AI coding tools like Claude, Cursor, and Copilot for credential access")
                FeatureRow(icon: "hand.raised", title: "Active Prevention", description: "Blocks malicious domains, quarantines files, and gates supply chain attacks")
                FeatureRow(icon: "lock.shield", title: "Privacy First", description: "Everything runs locally — no data ever leaves your machine")
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

            Text("You're All Set!")
                .font(.title2).fontWeight(.bold)

            Text("MacCrab is ready to protect your Mac.")
                .font(.callout)
                .foregroundColor(.secondary)

            VStack(alignment: .leading, spacing: 8) {
                SetupRow(icon: "checkmark.circle.fill", color: .green, text: "Detection engine active")
                SetupRow(icon: "checkmark.circle.fill", color: .green, text: "273 rules loaded")
                SetupRow(icon: "checkmark.circle.fill", color: .green, text: "Language: \(languages.first { $0.code == selectedLanguage }?.native ?? "English")")
                SetupRow(icon: "info.circle", color: .blue, text: "Start the daemon: sudo maccrabd")
                SetupRow(icon: "info.circle", color: .blue, text: "Enable prevention in the Prevention tab")
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
            Text(text)
                .font(.callout)
        }
    }
}
