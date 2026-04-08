// SuppressionManagerView.swift
// MacCrabApp
//
// Manages active alert suppressions — view and remove suppression patterns.

import SwiftUI

struct SuppressionManagerView: View {
    @ObservedObject var appState: AppState
    @State private var confirmRemoveAll = false

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Text(String(localized: "suppression.title", defaultValue: "Active Suppressions"))
                    .font(.headline)
                Spacer()
                if !appState.suppressionPatterns.isEmpty {
                    Button(role: .destructive) {
                        confirmRemoveAll = true
                    } label: {
                        Text(String(localized: "suppression.removeAll", defaultValue: "Remove All"))
                            .font(.caption)
                    }
                    .confirmationDialog(String(localized: "suppression.confirmTitle", defaultValue: "Remove all suppressions?"), isPresented: $confirmRemoveAll) {
                        Button(String(localized: "suppression.confirmButton", defaultValue: "Remove All Suppressions"), role: .destructive) {
                            removeAllSuppressions()
                        }
                    } message: {
                        Text(String(localized: "suppression.confirmMessage", defaultValue: "This will unsuppress all alerts. They will reappear in the dashboard."))
                    }
                }
            }

            Text(String(localized: "suppression.hint", defaultValue: "Suppressed patterns hide matching alerts from the dashboard. Remove a pattern to see those alerts again."))
                .font(.caption)
                .foregroundColor(.secondary)

            Divider()

            if appState.suppressionPatterns.isEmpty {
                VStack(spacing: 8) {
                    Image(systemName: "eye")
                        .font(.title2)
                        .foregroundColor(.secondary.opacity(0.5))
                        .accessibilityHidden(true)
                    Text(String(localized: "suppression.noActive", defaultValue: "No active suppressions"))
                        .font(.subheadline)
                        .foregroundColor(.secondary)
                }
                .frame(maxWidth: .infinity)
                .padding()
            } else {
                ScrollView {
                    VStack(spacing: 8) {
                        ForEach(Array(appState.suppressionPatterns.enumerated()), id: \.offset) { index, pattern in
                            HStack(spacing: 10) {
                                Image(systemName: "eye.slash")
                                    .foregroundColor(.secondary)
                                    .font(.subheadline)
                                    .accessibilityHidden(true)

                                VStack(alignment: .leading, spacing: 2) {
                                    Text(pattern.ruleTitle)
                                        .font(.subheadline)
                                        .fontWeight(.medium)
                                        .lineLimit(1)
                                    Text(String(format: String(localized: "suppression.process", defaultValue: "Process: %@"), pattern.processName))
                                        .font(.caption)
                                        .foregroundColor(.secondary)
                                }

                                Spacer()

                                Button {
                                    unsuppress(pattern: pattern)
                                } label: {
                                    Label(String(localized: "suppression.unsuppress", defaultValue: "Unsuppress"), systemImage: "eye")
                                        .font(.caption)
                                }
                                .buttonStyle(.bordered)
                                .controlSize(.small)
                            }
                            .padding(8)
                            .background(Color.secondary.opacity(0.05))
                            .cornerRadius(8)
                        }
                    }
                }
            }
        }
        .padding()
        .frame(width: 400, height: min(CGFloat(appState.suppressionPatterns.count) * 60 + 150, 400))
    }

    private func unsuppress(pattern: (ruleTitle: String, processName: String)) {
        appState.unsuppressPattern(ruleTitle: pattern.ruleTitle, processName: pattern.processName)
        // Re-mark alerts as not suppressed
        for i in appState.dashboardAlerts.indices {
            if appState.dashboardAlerts[i].ruleTitle == pattern.ruleTitle &&
               appState.dashboardAlerts[i].processName == pattern.processName {
                appState.dashboardAlerts[i].suppressed = false
            }
        }
    }

    private func removeAllSuppressions() {
        let patterns = appState.suppressionPatterns
        for pattern in patterns {
            unsuppress(pattern: pattern)
        }
    }
}
