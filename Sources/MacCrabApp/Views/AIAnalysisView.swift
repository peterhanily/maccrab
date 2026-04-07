// AIAnalysisView.swift
// MacCrabApp
//
// Displays LLM-generated investigation summaries and defense recommendations.
// Shows AI backend status and provides on-demand analysis.

import SwiftUI
import MacCrabCore

struct AIAnalysisView: View {
    @ObservedObject var appState: AppState
    @State private var huntQuery: String = ""
    @State private var huntResult: String = ""
    @State private var isHunting: Bool = false
    @State private var selectedAnalysis: AlertViewModel? = nil

    private var investigations: [AlertViewModel] {
        appState.aiAnalysisAlerts.filter { $0.ruleTitle.hasPrefix("Investigation Summary:") }
    }

    private var recommendations: [AlertViewModel] {
        appState.aiAnalysisAlerts.filter { $0.ruleTitle.hasPrefix("Defense Recommendation:") }
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                // Header
                HStack {
                    Text(String(localized: "aiAnalysis.title", defaultValue: "AI Analysis"))
                        .font(.title2).fontWeight(.bold)
                    Spacer()
                    llmStatusBadge
                }
                .padding(.horizontal)
                .padding(.top)

                // Status
                if !appState.llmStatus.isConfigured {
                    unconfiguredBanner
                } else {
                    // Threat Hunt section
                    threatHuntSection

                    Divider().padding(.horizontal)

                    // Investigation Summaries
                    if !investigations.isEmpty {
                        analysisSection(
                            title: String(localized: "aiAnalysis.investigations", defaultValue: "Investigation Summaries"),
                            icon: "doc.text.magnifyingglass",
                            alerts: investigations
                        )

                        Divider().padding(.horizontal)
                    }

                    // Defense Recommendations
                    if !recommendations.isEmpty {
                        analysisSection(
                            title: String(localized: "aiAnalysis.recommendations", defaultValue: "Defense Recommendations"),
                            icon: "shield.checkered",
                            alerts: recommendations
                        )

                        Divider().padding(.horizontal)
                    }

                    if investigations.isEmpty && recommendations.isEmpty {
                        VStack(spacing: 12) {
                            Spacer()
                            Image(systemName: "brain")
                                .font(.system(size: 48))
                                .foregroundColor(.secondary.opacity(0.5))
                            Text(String(localized: "aiAnalysis.noAnalysis", defaultValue: "No AI analysis yet"))
                                .font(.headline)
                                .foregroundColor(.secondary)
                            Text(String(localized: "aiAnalysis.noAnalysisDetail", defaultValue: "Investigation summaries and defense recommendations appear here when campaigns are detected."))
                                .font(.subheadline)
                                .foregroundColor(.secondary)
                                .multilineTextAlignment(.center)
                            Spacer()
                        }
                        .frame(maxWidth: .infinity)
                        .padding(40)
                    }
                }

                Spacer()
            }
        }
    }

    // MARK: - Components

    private var llmStatusBadge: some View {
        HStack(spacing: 6) {
            Circle()
                .fill(appState.llmStatus.isConfigured ? Color.green : Color.secondary)
                .frame(width: 8, height: 8)
            Text(appState.llmStatus.isConfigured
                ? appState.llmStatus.provider.capitalized
                : String(localized: "aiAnalysis.notConfigured", defaultValue: "Not configured"))
                .font(.caption)
                .foregroundColor(appState.llmStatus.isConfigured ? .primary : .secondary)
        }
    }

    private var unconfiguredBanner: some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 8) {
                HStack {
                    Image(systemName: "brain")
                        .font(.title2)
                        .foregroundColor(.secondary)
                    Text(String(localized: "aiAnalysis.setupTitle", defaultValue: "AI Analysis Backend"))
                        .font(.headline)
                }

                Text(String(localized: "aiAnalysis.setupDesc", defaultValue: "Connect an LLM backend to enable AI-powered threat hunting, investigation summaries, and defense recommendations."))
                    .font(.callout)
                    .foregroundColor(.secondary)

                Divider()

                VStack(alignment: .leading, spacing: 4) {
                    Text(String(localized: "aiAnalysis.setupOllama", defaultValue: "Local (recommended):"))
                        .font(.caption).fontWeight(.medium)
                    Text("MACCRAB_LLM_PROVIDER=ollama")
                        .font(.system(.caption, design: .monospaced))
                        .foregroundColor(.secondary)
                        .textSelection(.enabled)
                }

                VStack(alignment: .leading, spacing: 4) {
                    Text(String(localized: "aiAnalysis.setupClaude", defaultValue: "Cloud (Claude API):"))
                        .font(.caption).fontWeight(.medium)
                    Text("MACCRAB_LLM_PROVIDER=claude MACCRAB_LLM_CLAUDE_KEY=sk-ant-...")
                        .font(.system(.caption, design: .monospaced))
                        .foregroundColor(.secondary)
                        .textSelection(.enabled)
                }

                Text(String(localized: "aiAnalysis.setupRestart", defaultValue: "Set environment variables before starting the daemon. Ollama runs fully on-device with no data leaving your machine."))
                    .font(.caption2)
                    .foregroundColor(.secondary)
            }
            .padding(4)
        }
        .padding(.horizontal)
    }

    private var threatHuntSection: some View {
        GroupBox(String(localized: "aiAnalysis.threatHunt", defaultValue: "AI Threat Hunt")) {
            VStack(alignment: .leading, spacing: 8) {
                Text(String(localized: "aiAnalysis.threatHuntDesc", defaultValue: "Ask questions about your security events in plain English. The AI translates your query into a database search."))
                    .font(.caption)
                    .foregroundColor(.secondary)

                HStack {
                    TextField(String(localized: "aiAnalysis.huntPlaceholder", defaultValue: "e.g., show me unsigned processes that made network connections today"), text: $huntQuery)
                        .textFieldStyle(.roundedBorder)
                        .onSubmit { performHunt() }

                    Button {
                        performHunt()
                    } label: {
                        Label(String(localized: "aiAnalysis.hunt", defaultValue: "Hunt"), systemImage: "magnifyingglass")
                    }
                    .disabled(huntQuery.isEmpty || isHunting)
                    .keyboardShortcut(.return, modifiers: .command)
                }

                if isHunting {
                    HStack {
                        ProgressView()
                            .scaleEffect(0.7)
                        Text(String(localized: "aiAnalysis.hunting", defaultValue: "Querying AI backend..."))
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }
                }

                if !huntResult.isEmpty {
                    GroupBox {
                        ScrollView {
                            Text(huntResult)
                                .font(.system(.caption, design: .monospaced))
                                .textSelection(.enabled)
                                .frame(maxWidth: .infinity, alignment: .leading)
                        }
                        .frame(maxHeight: 300)
                    }
                }
            }
            .padding(4)
        }
        .padding(.horizontal)
    }

    private func analysisSection(title: String, icon: String, alerts: [AlertViewModel]) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Image(systemName: icon)
                    .foregroundColor(.accentColor)
                Text(title)
                    .font(.headline)
                Text("(\(alerts.count))")
                    .font(.caption)
                    .foregroundColor(.secondary)
            }
            .padding(.horizontal)

            ForEach(alerts, id: \.id) { alert in
                AnalysisCard(alert: alert, isExpanded: selectedAnalysis == alert) {
                    withAnimation(.easeInOut(duration: 0.2)) {
                        selectedAnalysis = selectedAnalysis == alert ? nil : alert
                    }
                }
            }
            .padding(.horizontal)
        }
    }

    // MARK: - Actions

    private func performHunt() {
        guard !huntQuery.isEmpty else { return }
        isHunting = true
        huntResult = ""

        Task {
            // Use maccrabctl hunt via Process since the app doesn't have direct DB access for LLM queries
            let process = Process()
            process.executableURL = URL(fileURLWithPath: "/usr/bin/env")

            // Find maccrabctl in common locations
            let paths = ["/usr/local/bin/maccrabctl", ".build/debug/maccrabctl"]
            let ctlPath = paths.first { FileManager.default.isExecutableFile(atPath: $0) } ?? "maccrabctl"

            process.arguments = [ctlPath, "hunt", huntQuery]
            // Pass through LLM env vars
            var env = ProcessInfo.processInfo.environment
            env["PATH"] = "/usr/local/bin:/usr/bin:/bin"
            process.environment = env

            let pipe = Pipe()
            process.standardOutput = pipe
            process.standardError = pipe

            do {
                try process.run()
                process.waitUntilExit()
                let data = pipe.fileHandleForReading.readDataToEndOfFile()
                let output = String(data: data, encoding: .utf8) ?? "No output"
                await MainActor.run {
                    huntResult = output
                    isHunting = false
                }
            } catch {
                await MainActor.run {
                    huntResult = "Error: \(error.localizedDescription)"
                    isHunting = false
                }
            }
        }
    }
}

// MARK: - Analysis Card

struct AnalysisCard: View {
    let alert: AlertViewModel
    let isExpanded: Bool
    let onTap: () -> Void

    private var displayTitle: String {
        alert.ruleTitle
            .replacingOccurrences(of: "Investigation Summary: ", with: "")
            .replacingOccurrences(of: "Defense Recommendation: ", with: "")
    }

    private var isRecommendation: Bool {
        alert.ruleTitle.hasPrefix("Defense Recommendation:")
    }

    var body: some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 8) {
                HStack {
                    Image(systemName: isRecommendation ? "shield.checkered" : "doc.text.magnifyingglass")
                        .foregroundColor(isRecommendation ? .orange : .accentColor)
                    Text(displayTitle)
                        .font(.callout).fontWeight(.medium)
                        .lineLimit(isExpanded ? nil : 1)
                    Spacer()
                    Text(alert.timeAgoString)
                        .font(.caption2)
                        .foregroundColor(.secondary)
                    Image(systemName: isExpanded ? "chevron.up" : "chevron.down")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
                .contentShape(Rectangle())
                .onTapGesture(perform: onTap)

                if isExpanded {
                    Divider()
                    Text(alert.description)
                        .font(.system(.caption, design: .monospaced))
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
            }
            .padding(4)
        }
    }
}
