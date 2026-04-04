// AlertDashboard.swift
// MacCrabApp

import SwiftUI

// MARK: - AlertDashboard

struct AlertDashboard: View {
    @ObservedObject var appState: AppState
    @State private var selectedSeverity: Severity? = nil
    @State private var searchText: String = ""
    @State private var showSuppressed: Bool = false
    @State private var selectedAlert: AlertViewModel? = nil

    private var filteredAlerts: [AlertViewModel] {
        var results = appState.dashboardAlerts
        if !showSuppressed {
            results = results.filter { !$0.suppressed }
        }
        if let severity = selectedSeverity {
            results = results.filter { $0.severity == severity }
        }
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

                ForEach([Severity.critical, .high, .medium, .low], id: \.self) { sev in
                    SeverityChip(severity: sev, isSelected: selectedSeverity == sev) {
                        selectedSeverity = selectedSeverity == sev ? nil : sev
                    }
                }

                Toggle("Suppressed", isOn: $showSuppressed)
                    .toggleStyle(.checkbox)
                    .font(.caption)

                TextField("Search...", text: $searchText)
                    .textFieldStyle(.roundedBorder)
                    .frame(width: 200)
            }
            .padding()

            Divider()

            // Alert list + detail panel
            if filteredAlerts.isEmpty {
                VStack(spacing: 12) {
                    Spacer()
                    Image(systemName: "shield.checkmark")
                        .font(.system(size: 48))
                        .foregroundColor(.secondary.opacity(0.5))
                    Text(appState.dashboardAlerts.isEmpty ? "No alerts — all clear" : "No alerts matching filters")
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
                HSplitView {
                    // Alert list
                    List(filteredAlerts, selection: $selectedAlert) { alert in
                        AlertRow(alert: alert) {
                            Task { await appState.suppressAlert(alert.id) }
                        }
                        .tag(alert)
                        .contentShape(Rectangle())
                        .onTapGesture { selectedAlert = alert }
                    }
                    .frame(minWidth: 400)

                    // Detail panel
                    if let alert = selectedAlert {
                        AlertDetailView(alert: alert) {
                            Task { await appState.suppressAlert(alert.id) }
                        }
                        .frame(minWidth: 300, idealWidth: 350)
                    } else {
                        VStack {
                            Spacer()
                            Text("Select an alert to see details")
                                .foregroundColor(.secondary)
                            Spacer()
                        }
                        .frame(minWidth: 300)
                    }
                }
            }
        }
        .task {
            await appState.loadAlerts()
        }
    }
}

// MARK: - Alert Detail View

struct AlertDetailView: View {
    let alert: AlertViewModel
    let onSuppress: () -> Void

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                // Severity + Time header
                HStack {
                    HStack(spacing: 6) {
                        Circle().fill(alert.severityColor).frame(width: 10, height: 10)
                        Text(alert.severity.label).font(.caption).fontWeight(.bold).foregroundColor(alert.severityColor)
                    }
                    .padding(.horizontal, 8).padding(.vertical, 3)
                    .background(alert.severityColor.opacity(0.1))
                    .clipShape(Capsule())
                    Spacer()
                    Text(alert.dateTimeString).font(.caption).foregroundColor(.secondary)
                }

                Text(alert.ruleTitle).font(.title3).fontWeight(.bold)

                // Description
                if !alert.description.isEmpty {
                    GroupBox("Description") {
                        Text(alert.description).font(.body).textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .leading).padding(4)
                    }
                }

                // Process details
                GroupBox("Process Details") {
                    VStack(alignment: .leading, spacing: 6) {
                        DetailRow(label: "Name", value: alert.processName)
                        DetailRow(label: "Path", value: alert.processPath)
                        if !alert.processPath.isEmpty {
                            DetailRow(label: "Directory", value: (alert.processPath as NSString).deletingLastPathComponent)
                        }
                    }.padding(4)
                }

                // MITRE ATT&CK
                if !alert.mitreTechniques.isEmpty {
                    GroupBox("MITRE ATT&CK") {
                        VStack(alignment: .leading, spacing: 6) {
                            let techniques = alert.mitreTechniques.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
                            ForEach(techniques, id: \.self) { tech in
                                HStack {
                                    Image(systemName: "shield.fill").foregroundColor(.orange).font(.caption)
                                    Text(tech).font(.system(.body, design: .monospaced))
                                    Spacer()
                                    Link("View", destination: URL(string: "https://attack.mitre.org/techniques/\(tech.replacingOccurrences(of: "attack.", with: "").uppercased().replacingOccurrences(of: ".", with: "/"))/")!)
                                        .font(.caption)
                                }
                            }
                        }.padding(4)
                    }
                }

                // Alert metadata
                GroupBox("Metadata") {
                    VStack(alignment: .leading, spacing: 6) {
                        DetailRow(label: "Alert ID", value: alert.id)
                        DetailRow(label: "Severity", value: alert.severity.label)
                        DetailRow(label: "Status", value: alert.suppressed ? "Suppressed" : "Active")
                    }.padding(4)
                }

                // Response Actions
                GroupBox("Response Actions") {
                    VStack(alignment: .leading, spacing: 8) {
                        HStack(spacing: 10) {
                            if !alert.suppressed {
                                Button { onSuppress() } label: {
                                    Label("Suppress Alert", systemImage: "eye.slash")
                                }.controlSize(.large)
                            } else {
                                Label("Suppressed", systemImage: "eye.slash.fill").foregroundColor(.secondary)
                            }

                            Button {
                                NSPasteboard.general.clearContents()
                                let text = """
                                Rule: \(alert.ruleTitle)
                                Alert ID: \(alert.id)
                                Severity: \(alert.severity.label)
                                Time: \(alert.dateTimeString)
                                Process: \(alert.processName) (\(alert.processPath))
                                MITRE: \(alert.mitreTechniques)
                                Description: \(alert.description)
                                """
                                NSPasteboard.general.setString(text, forType: .string)
                            } label: {
                                Label("Copy Details", systemImage: "doc.on.doc")
                            }.controlSize(.large)
                        }

                        Divider()

                        Text("Configurable Actions").font(.caption).foregroundColor(.secondary)
                        Text("Configure response actions in ~/Library/Application Support/MacCrab/actions.json")
                            .font(.caption2).foregroundColor(.secondary)
                        HStack(spacing: 16) {
                            ActionBadge(icon: "xmark.circle", label: "Kill Process", color: .red)
                            ActionBadge(icon: "archivebox", label: "Quarantine", color: .orange)
                            ActionBadge(icon: "terminal", label: "Run Script", color: .blue)
                            ActionBadge(icon: "bell", label: "Notify", color: .green)
                        }
                    }.padding(4)
                }

                Spacer()
            }.padding()
        }.background(Color(nsColor: .controlBackgroundColor))
    }
}

private struct ActionBadge: View {
    let icon: String
    let label: String
    let color: Color
    var body: some View {
        VStack(spacing: 4) {
            Image(systemName: icon).font(.title3).foregroundColor(color)
            Text(label).font(.caption2).foregroundColor(.secondary)
        }
        .frame(width: 70)
        .padding(6)
        .background(color.opacity(0.06))
        .clipShape(RoundedRectangle(cornerRadius: 6))
    }
}

struct DetailRow: View {
    let label: String
    let value: String

    var body: some View {
        HStack(alignment: .top) {
            Text(label)
                .font(.caption)
                .foregroundColor(.secondary)
                .frame(width: 50, alignment: .trailing)
            Text(value)
                .font(.system(.body, design: .monospaced))
                .textSelection(.enabled)
        }
    }
}
