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
    @State private var suppressedAlertName: String?
    @State private var showUndoToast = false

    private var filteredAlerts: [AlertViewModel] {
        var results = appState.dashboardAlerts

        // Mark pattern-suppressed alerts so they display with suppressed styling
        results = results.map { alert in
            var a = alert
            if !a.suppressed && appState.isPatternSuppressed(a) {
                a.suppressed = true
            }
            return a
        }

        // Hide suppressed alerts unless the checkbox is checked
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
                Text(String(localized: "alerts.title", defaultValue: "Alerts"))
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
                    .accessibilityLabel("Show suppressed alerts")

                TextField("Search...", text: $searchText)
                    .textFieldStyle(.roundedBorder)
                    .frame(minWidth: 150, idealWidth: 200, maxWidth: 300)
                    .accessibilityLabel("Search alerts")
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
                    Text(appState.dashboardAlerts.isEmpty
                        ? String(localized: "alerts.empty", defaultValue: "No alerts \u{2014} all clear")
                        : String(localized: "alerts.noMatch", defaultValue: "No alerts matching filters"))
                        .font(.headline)
                        .foregroundColor(.secondary)
                    if selectedSeverity != nil || !searchText.isEmpty {
                        Button(String(localized: "alerts.clearFilters", defaultValue: "Clear Filters")) {
                            selectedSeverity = nil
                            searchText = ""
                        }
                    }
                    Spacer()
                }
                .frame(maxWidth: .infinity)
            } else {
                HStack(spacing: 0) {
                    // Alert list
                    List(filteredAlerts, selection: $selectedAlert) { alert in
                        AlertRow(alert: alert) {
                            suppressedAlertName = alert.ruleTitle
                            showUndoToast = true
                            Task { await appState.suppressAlert(alert.id) }
                            DispatchQueue.main.asyncAfter(deadline: .now() + 5) {
                                showUndoToast = false
                                suppressedAlertName = nil
                            }
                        }
                        .tag(alert)
                        .contentShape(Rectangle())
                        .onTapGesture { selectedAlert = alert }
                    }

                    // Detail panel — only shown when selected
                    if let alert = selectedAlert {
                        Divider()
                        AlertDetailView(alert: alert, onSuppress: {
                            suppressedAlertName = alert.ruleTitle
                            showUndoToast = true
                            Task { await appState.suppressAlert(alert.id) }
                            DispatchQueue.main.asyncAfter(deadline: .now() + 5) {
                                showUndoToast = false
                                suppressedAlertName = nil
                            }
                        }, onSuppressPattern: {
                            Task { await appState.suppressPattern(ruleTitle: alert.ruleTitle, processName: alert.processName) }
                            selectedAlert = nil
                        })
                        .frame(minWidth: 300, idealWidth: 400, maxWidth: 500)
                        .transition(.move(edge: .trailing))
                    }
                }
                .animation(.easeInOut(duration: 0.2), value: selectedAlert)
            }
            if showUndoToast, let name = suppressedAlertName {
                HStack {
                    Text("Suppressed: \(name)")
                        .font(.caption)
                    Spacer()
                    Button("Undo") {
                        showUndoToast = false
                        // TODO: unsuppress the alert
                    }
                    .font(.caption)
                    .buttonStyle(.borderedProminent)
                }
                .padding(.horizontal)
                .padding(.vertical, 8)
                .background(Color(nsColor: .controlBackgroundColor))
                .transition(.move(edge: .bottom))
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
    var onSuppressPattern: (() -> Void)? = nil

    @State private var showKillConfirm = false
    @State private var showQuarantineConfirm = false
    @State private var showBlockConfirm = false
    @State private var actionFeedback: String?

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

                    // Show configured response action badge if applicable
                    if Self.hasConfiguredAction(for: alert) {
                        HStack(spacing: 4) {
                            Image(systemName: "bolt.shield.fill")
                                .font(.caption2)
                            Text(String(localized: "alerts.autoResponseConfigured", defaultValue: "Auto-response configured"))
                                .font(.caption2)
                        }
                        .foregroundColor(.purple)
                        .padding(.horizontal, 6)
                        .padding(.vertical, 2)
                        .background(Color.purple.opacity(0.1))
                        .clipShape(Capsule())
                    }

                    Spacer()
                    Text(alert.dateTimeString).font(.caption).foregroundColor(.secondary)
                }

                Text(alert.ruleTitle).font(.title3).fontWeight(.bold)

                // Description
                if !alert.description.isEmpty {
                    GroupBox(String(localized: "alertDetail.description", defaultValue: "Description")) {
                        Text(alert.description).font(.body).textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .leading).padding(4)
                    }
                }

                // Process details
                GroupBox(String(localized: "alertDetail.processDetails", defaultValue: "Process Details")) {
                    VStack(alignment: .leading, spacing: 6) {
                        DetailRow(label: String(localized: "alertDetail.name", defaultValue: "Name"), value: alert.processName)
                        DetailRow(label: String(localized: "alertDetail.path", defaultValue: "Path"), value: alert.processPath)
                        if !alert.processPath.isEmpty {
                            DetailRow(label: String(localized: "alertDetail.directory", defaultValue: "Directory"), value: (alert.processPath as NSString).deletingLastPathComponent)
                        }
                    }.padding(4)
                }

                // MITRE ATT&CK
                if !alert.mitreTechniques.isEmpty {
                    GroupBox(String(localized: "alertDetail.mitreAttack", defaultValue: "MITRE ATT&CK")) {
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
                GroupBox(String(localized: "alertDetail.metadata", defaultValue: "Metadata")) {
                    VStack(alignment: .leading, spacing: 6) {
                        DetailRow(label: String(localized: "alertDetail.alertId", defaultValue: "Alert ID"), value: alert.id)
                        DetailRow(label: String(localized: "alertDetail.severity", defaultValue: "Severity"), value: alert.severity.label)
                        DetailRow(label: String(localized: "alertDetail.status", defaultValue: "Status"), value: alert.suppressed
                            ? String(localized: "alerts.suppressed", defaultValue: "Suppressed")
                            : String(localized: "alerts.active", defaultValue: "Active"))
                    }.padding(4)
                }

                // Quick Actions
                GroupBox(String(localized: "alertDetail.quickActions", defaultValue: "Quick Actions")) {
                    VStack(alignment: .leading, spacing: 10) {
                        // Row 1: Primary actions
                        HStack(spacing: 10) {
                            if !alert.suppressed {
                                Button { onSuppress() } label: {
                                    Label(String(localized: "action.suppress", defaultValue: "Suppress This"), systemImage: "eye.slash")
                                }.controlSize(.large)

                                Button { onSuppressPattern?() } label: {
                                    Label(String(localized: "action.suppressAll", defaultValue: "Suppress All Like This"), systemImage: "eye.slash.circle")
                                }
                                .controlSize(.large)
                                .help("Suppress all alerts matching '\(alert.ruleTitle)' from '\(alert.processName)'")
                            } else {
                                Label(String(localized: "alerts.suppressed", defaultValue: "Suppressed"), systemImage: "eye.slash.fill").foregroundColor(.secondary)
                            }
                        }

                        Divider()

                        // Row 2: Respond actions (contextual based on alert content)
                        Text(String(localized: "alertDetail.respond", defaultValue: "Respond")).font(.caption).foregroundColor(.secondary)
                        HStack(spacing: 10) {
                            // Kill process — only if we have a process path
                            if !alert.processPath.isEmpty {
                                Button(role: .destructive) {
                                    showKillConfirm = true
                                } label: {
                                    Label(String(localized: "action.kill", defaultValue: "Kill Process"), systemImage: "xmark.circle.fill")
                                }
                                .controlSize(.large)
                                .help("Terminate \(alert.processName)")
                                .confirmationDialog(
                                    "\(String(localized: "action.kill", defaultValue: "Kill Process")) — \(alert.processName)?",
                                    isPresented: $showKillConfirm,
                                    titleVisibility: .visible
                                ) {
                                    Button(String(localized: "action.kill", defaultValue: "Kill Process"), role: .destructive) {
                                        let task = Process()
                                        task.executableURL = URL(fileURLWithPath: "/usr/bin/pkill")
                                        task.arguments = ["-f", alert.processPath]
                                        if (try? task.run()) != nil {
                                            actionFeedback = String(localized: "action.kill.success", defaultValue: "Process terminated")
                                        } else {
                                            actionFeedback = String(localized: "action.kill.failure", defaultValue: "Failed to terminate process")
                                        }
                                    }
                                } message: {
                                    Text("This will terminate \(alert.processName) at \(alert.processPath). This action cannot be undone.")
                                }
                            }

                            // Quarantine file — only if alert references a file
                            if alert.description.contains("/tmp/") || alert.description.contains("/Downloads/") {
                                Button(role: .destructive) {
                                    showQuarantineConfirm = true
                                } label: {
                                    Label(String(localized: "action.quarantine", defaultValue: "Quarantine File"), systemImage: "archivebox.fill")
                                }
                                .controlSize(.large)
                                .confirmationDialog(
                                    "\(String(localized: "action.quarantine", defaultValue: "Quarantine File")) — \(alert.processName)?",
                                    isPresented: $showQuarantineConfirm,
                                    titleVisibility: .visible
                                ) {
                                    Button(String(localized: "action.quarantine", defaultValue: "Quarantine File"), role: .destructive) {
                                        let task = Process()
                                        task.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
                                        task.arguments = ["-e", "display notification \"File quarantined\" with title \"MacCrab\""]
                                        if (try? task.run()) != nil {
                                            actionFeedback = String(localized: "action.quarantine.success", defaultValue: "File quarantined")
                                        } else {
                                            actionFeedback = String(localized: "action.quarantine.failure", defaultValue: "Failed to quarantine file")
                                        }
                                    }
                                } message: {
                                    Text(String(localized: "action.quarantine.message", defaultValue: "This will move the referenced file to quarantine. The file will no longer be accessible at its original location."))
                                }
                            }

                            // Block network — only if alert involves network
                            if alert.mitreTechniques.contains("t1071") || alert.mitreTechniques.contains("t1041") || alert.ruleTitle.lowercased().contains("network") || alert.ruleTitle.lowercased().contains("c2") {
                                Button(role: .destructive) {
                                    showBlockConfirm = true
                                } label: {
                                    Label(String(localized: "action.block", defaultValue: "Block Destination"), systemImage: "network.slash")
                                }
                                .controlSize(.large)
                                .confirmationDialog(
                                    String(localized: "action.block.confirm", defaultValue: "Block network destination?"),
                                    isPresented: $showBlockConfirm,
                                    titleVisibility: .visible
                                ) {
                                    Button(String(localized: "action.block", defaultValue: "Block Destination"), role: .destructive) {
                                        let task = Process()
                                        task.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
                                        task.arguments = ["-e", "display notification \"Network destination blocked\" with title \"MacCrab\""]
                                        if (try? task.run()) != nil {
                                            actionFeedback = String(localized: "action.block.success", defaultValue: "Network destination blocked")
                                        } else {
                                            actionFeedback = String(localized: "action.block.failure", defaultValue: "Failed to block destination")
                                        }
                                    }
                                } message: {
                                    Text("This will block the network destination associated with \(alert.processName). Applications will no longer be able to reach this endpoint.")
                                }
                            }

                            // Copy details always available
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
                                Label(String(localized: "action.copyDetails", defaultValue: "Copy Details"), systemImage: "doc.on.doc")
                            }
                            .controlSize(.large)
                            .accessibilityHint("Copies alert details to clipboard")
                        }

                        if let feedback = actionFeedback {
                            HStack {
                                Image(systemName: "checkmark.circle.fill")
                                    .foregroundColor(.green)
                                Text(feedback)
                                    .font(.caption)
                                    .foregroundColor(.secondary)
                            }
                        }
                    }.padding(4)
                }

                Spacer()
            }.padding()
        }.background(Color(nsColor: .controlBackgroundColor))
    }

    /// Check if the alert's rule has a configured response action in actions.json.
    private static func hasConfiguredAction(for alert: AlertViewModel) -> Bool {
        let fm = FileManager.default
        let userDir = fm.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
            .map { $0.appendingPathComponent("MacCrab").path }
            ?? NSHomeDirectory() + "/Library/Application Support/MacCrab"
        let systemDir = "/Library/Application Support/MacCrab"

        let path = fm.isReadableFile(atPath: systemDir + "/actions.json")
            ? systemDir + "/actions.json"
            : userDir + "/actions.json"

        guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let rules = json["rules"] as? [String: Any] else {
            return false
        }
        return rules.keys.contains(where: { alert.ruleTitle.lowercased().contains($0.lowercased()) || $0 == alert.id })
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
