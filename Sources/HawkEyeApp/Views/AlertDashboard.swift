// AlertDashboard.swift
// HawkEyeApp
//
// Alert timeline view showing all detection alerts with severity filtering,
// search, and suppress capabilities.

import SwiftUI

// MARK: - AlertDashboard

struct AlertDashboard: View {
    @ObservedObject var appState: AppState
    @State private var selectedSeverity: Severity? = nil
    @State private var searchText: String = ""
    @State private var showSuppressed: Bool = false

    /// Alerts filtered by current severity selection, search text, and suppression toggle.
    private var filteredAlerts: [AlertViewModel] {
        var results = appState.dashboardAlerts

        // Filter by suppression state
        if !showSuppressed {
            results = results.filter { !$0.suppressed }
        }

        // Filter by severity
        if let severity = selectedSeverity {
            results = results.filter { $0.severity == severity }
        }

        // Filter by search text
        if !searchText.isEmpty {
            let query = searchText.lowercased()
            results = results.filter { alert in
                alert.ruleTitle.lowercased().contains(query)
                    || alert.processName.lowercased().contains(query)
                    || alert.processPath.lowercased().contains(query)
                    || alert.description.lowercased().contains(query)
                    || alert.mitreTechniques.lowercased().contains(query)
            }
        }

        return results
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            // Header with severity filter chips and search
            HStack(spacing: 12) {
                Text("Alerts")
                    .font(.title2)
                    .fontWeight(.bold)

                Text("\(filteredAlerts.count)")
                    .font(.caption)
                    .padding(.horizontal, 8)
                    .padding(.vertical, 2)
                    .background(Color.secondary.opacity(0.2))
                    .clipShape(Capsule())

                Spacer()

                // Severity filter buttons
                ForEach([Severity.critical, .high, .medium, .low], id: \.self) { sev in
                    SeverityChip(severity: sev, isSelected: selectedSeverity == sev) {
                        selectedSeverity = selectedSeverity == sev ? nil : sev
                    }
                    .accessibilityLabel("\(sev.rawValue) severity filter")
                    .accessibilityHint("Double tap to filter alerts by \(sev.rawValue) severity")
                }

                Toggle("Suppressed", isOn: $showSuppressed)
                    .toggleStyle(.checkbox)
                    .font(.caption)

                TextField("Search...", text: $searchText)
                    .textFieldStyle(.roundedBorder)
                    .frame(width: 200)
                    .accessibilityLabel("Search alerts")
            }
            .padding()

            Divider()

            // Alert list
            if filteredAlerts.isEmpty {
                VStack(spacing: 12) {
                    Spacer()
                    Image(systemName: "shield.checkmark")
                        .font(.system(size: 48))
                        .foregroundColor(.secondary.opacity(0.5))
                    Text("No alerts matching current filters")
                        .font(.headline)
                        .foregroundColor(.secondary)
                    if selectedSeverity != nil || !searchText.isEmpty {
                        Button("Clear Filters") {
                            selectedSeverity = nil
                            searchText = ""
                        }
                    }
                    Spacer()
                }
                .frame(maxWidth: .infinity)
            } else {
                List(filteredAlerts) { alert in
                    AlertRow(alert: alert) {
                        suppressAlert(alert)
                    }
                }
            }
        }
        .task {
            await appState.loadAlerts()
        }
    }

    // MARK: Private

    private func suppressAlert(_ alert: AlertViewModel) {
        Task {
            await appState.suppressAlert(alert.id)
        }
    }
}

// MARK: - Preview

#Preview {
    AlertDashboard(appState: AppState())
        .frame(width: 900, height: 600)
}
