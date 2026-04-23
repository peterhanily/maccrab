// AlertDashboard.swift
// MacCrabApp

import SwiftUI
import MacCrabCore

// MARK: - AlertDashboard

struct AlertDashboard: View {
    @ObservedObject var appState: AppState
    // Persisted across tab switches and app restarts. Empty string = no filter.
    @AppStorage("alerts.selectedSeverity") private var selectedSeverityRaw: String = ""
    @AppStorage("alerts.showSuppressed") private var showSuppressed: Bool = false
    @State private var searchText: String = ""
    @State private var selectedAlerts: Set<AlertViewModel> = []
    @State private var suppressedAlertName: String?
    @State private var showUndoToast = false
    /// IDs to unsuppress if the user taps Undo on the toast (single, bulk, or pattern).
    @State private var undoAlertIDs: [String] = []
    @State private var exportInProgress = false
    @State private var showSuppressionManager = false
    @Environment(\.accessibilityReduceMotion) var reduceMotion

    /// Derived severity filter from the persisted raw value.
    private var selectedSeverity: Severity? {
        get { Severity(rawValue: selectedSeverityRaw) }
    }

    private func setSelectedSeverity(_ sev: Severity?) {
        selectedSeverityRaw = sev?.rawValue ?? ""
    }

    /// Single selected alert for the detail panel (last selected)
    private var detailAlert: AlertViewModel? {
        selectedAlerts.count == 1 ? selectedAlerts.first : nil
    }

    private var filteredAlerts: [AlertViewModel] {
        // Inline helper — the authoritative "is this alert effectively
        // suppressed?" check that overlays session-level state on top of
        // whatever the DB returned. Kept as a closure so both the filter
        // path (when hiding suppressed) and the display-annotation path
        // (when showing them) use the same logic.
        let isEffectivelySuppressed: (AlertViewModel) -> Bool = { [appState] alert in
            alert.suppressed
                || appState.suppressedIDs.contains(alert.id)
                || appState.isPatternSuppressed(alert)
        }

        let query = searchText.isEmpty ? nil : searchText.lowercased()

        // Single-pass filter using lazy evaluation — no intermediate array
        // allocations, no per-keystroke full-array rebuild. Campaigns are
        // excluded structurally (they have their own tab). The old
        // implementation rebuilt a 500-element AlertViewModel array every
        // keystroke via .map before filtering; that was the hot path.
        let filteredLazy = appState.dashboardAlerts.lazy.filter { alert in
            if alert.ruleId.hasPrefix("maccrab.campaign.") { return false }
            if !showSuppressed && isEffectivelySuppressed(alert) { return false }
            if let sev = selectedSeverity, alert.severity != sev { return false }
            if let q = query {
                let hay = "\(alert.ruleTitle) \(alert.processName) \(alert.processPath) \(alert.description) \(alert.mitreTechniques)".lowercased()
                if !hay.contains(q) { return false }
            }
            return true
        }

        // Only materialize the effective-suppressed annotation when the user
        // has explicitly asked to see suppressed rows; otherwise the filter
        // already excluded them, so the stored `suppressed` flag is accurate.
        if showSuppressed {
            return filteredLazy.map { alert -> AlertViewModel in
                guard !alert.suppressed, isEffectivelySuppressed(alert) else { return alert }
                var a = alert
                a.suppressed = true
                return a
            }
        }
        return Array(filteredLazy)
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
                        setSelectedSeverity(selectedSeverity == sev ? nil : sev)
                    }
                }

                Toggle("Suppressed", isOn: $showSuppressed)
                    .toggleStyle(.checkbox)
                    .font(.caption)
                    .accessibilityLabel("Show suppressed alerts")

                if !appState.suppressionPatterns.isEmpty {
                    Button {
                        showSuppressionManager = true
                    } label: {
                        Label("Manage (\(appState.suppressionPatterns.count))", systemImage: "eye.slash.circle")
                    }
                    .font(.caption)
                    .popover(isPresented: $showSuppressionManager) {
                        SuppressionManagerView(appState: appState)
                    }
                }

                TextField("Search...", text: $searchText)
                    .textFieldStyle(.roundedBorder)
                    .frame(minWidth: 150, idealWidth: 200, maxWidth: 300)
                    .accessibilityLabel("Search alerts")

                if !filteredAlerts.isEmpty {
                    Button(String(localized: "alerts.selectAll", defaultValue: "Select All")) {
                        selectedAlerts = Set(filteredAlerts)
                    }
                    .controlSize(.small)
                    .disabled(filteredAlerts.allSatisfy { selectedAlerts.contains($0) })
                }

                Menu {
                    Button("JSON") { exportAlerts(format: .json) }
                    Button("CSV") { exportAlerts(format: .csv) }
                    Button("SARIF (GitHub)") { exportAlerts(format: .sarif) }
                    Button("CEF (ArcSight)") { exportAlerts(format: .cef) }
                    Button("LEEF (QRadar)") { exportAlerts(format: .leef) }
                    Button("STIX 2.1") { exportAlerts(format: .stix) }
                    Divider()
                    Button("HTML Report") { exportHTMLReport() }
                } label: {
                    Label("Export", systemImage: "square.and.arrow.up")
                }
                .menuStyle(.borderlessButton)
                .frame(width: 80)
                .disabled(filteredAlerts.isEmpty || exportInProgress)
                .accessibilityLabel("Export alerts")
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
                        .accessibilityHidden(true)
                    Text(appState.dashboardAlerts.isEmpty
                        ? String(localized: "alerts.empty", defaultValue: "No alerts \u{2014} all clear")
                        : String(localized: "alerts.noMatch", defaultValue: "No alerts matching filters"))
                        .font(.headline)
                        .foregroundColor(.secondary)
                    if selectedSeverity != nil || !searchText.isEmpty {
                        Button(String(localized: "alerts.clearFilters", defaultValue: "Clear Filters")) {
                            setSelectedSeverity(nil)
                            searchText = ""
                        }
                    }
                    Spacer()
                }
                .frame(maxWidth: .infinity)
            } else {
                HStack(spacing: 0) {
                    VStack(spacing: 0) {
                        // Bulk action bar (visible when multiple selected)
                        if selectedAlerts.count > 1 {
                            HStack(spacing: 12) {
                                Text("\(selectedAlerts.count) selected")
                                    .font(.caption)
                                    .fontWeight(.medium)

                                let hasUnsuppressed = selectedAlerts.contains { !$0.suppressed }
                                let hasSuppressed = selectedAlerts.contains { $0.suppressed }

                                if hasUnsuppressed {
                                    Button {
                                        bulkSuppress()
                                    } label: {
                                        Label("Suppress Selected", systemImage: "eye.slash")
                                    }
                                    .controlSize(.small)
                                }

                                if hasSuppressed {
                                    Button {
                                        bulkUnsuppress()
                                    } label: {
                                        Label("Unsuppress Selected", systemImage: "eye")
                                    }
                                    .controlSize(.small)
                                }

                                Button {
                                    selectedAlerts = []
                                } label: {
                                    Text(String(localized: "alerts.deselectAll", defaultValue: "Deselect All"))
                                }
                                .controlSize(.small)
                                .buttonStyle(.plain)
                                .foregroundColor(.accentColor)

                                Spacer()

                                Text(String(localized: "alerts.multiSelectHint", defaultValue: "Shift+click to range select, Cmd+click to toggle"))
                                    .font(.caption2)
                                    .foregroundColor(.secondary)
                            }
                            .padding(.horizontal)
                            .padding(.vertical, 6)
                            .background(.bar)
                        }

                        // Alert list with multi-selection (Cmd+click, Shift+click, Cmd+A)
                        List(filteredAlerts, selection: $selectedAlerts) { alert in
                            AlertRow(alert: alert) {
                                presentSuppressToast(names: [alert.ruleTitle], ids: [alert.id])
                                Task { await appState.suppressAlert(alert.id) }
                            }
                            .tag(alert)
                        }
                    }

                    // Detail panel — shown when exactly one alert selected
                    if let alert = detailAlert {
                        Divider()
                        AlertDetailView(alert: alert, appState: appState, onSuppress: {
                            presentSuppressToast(names: [alert.ruleTitle], ids: [alert.id])
                            Task { await appState.suppressAlert(alert.id) }
                        }, onUnsuppress: {
                            Task { await appState.unsuppressAlert(alert.id) }
                        }, onSuppressPattern: {
                            Task { await appState.suppressPattern(ruleTitle: alert.ruleTitle, processName: alert.processName) }
                            selectedAlerts = []
                        })
                        .frame(minWidth: 300, idealWidth: 400, maxWidth: 500)
                        .transition(reduceMotion ? .opacity : .move(edge: .trailing))
                    }
                }
                .animation(reduceMotion ? nil : .easeInOut(duration: 0.2), value: detailAlert)
            }
            if showUndoToast, let name = suppressedAlertName {
                HStack(spacing: 12) {
                    Image(systemName: "eye.slash.fill")
                        .foregroundColor(.secondary)
                        .accessibilityHidden(true)
                    Text(String(localized: "alerts.suppressedToast", defaultValue: "Suppressed: \(name)"))
                        .font(.caption)
                    Spacer()
                    if !undoAlertIDs.isEmpty {
                        Button {
                            undoLastSuppress()
                        } label: {
                            Label(
                                String(localized: "alerts.undoSuppress", defaultValue: "Undo"),
                                systemImage: "arrow.uturn.backward"
                            )
                        }
                        .font(.caption)
                        .buttonStyle(.borderedProminent)
                        .keyboardShortcut("z", modifiers: .command)
                    }
                    Button {
                        dismissSuppressToast()
                    } label: {
                        Image(systemName: "xmark")
                            .foregroundColor(.secondary)
                    }
                    .buttonStyle(.borderless)
                    .accessibilityLabel(String(localized: "alerts.dismissToast", defaultValue: "Dismiss"))
                }
                .padding(.horizontal)
                .padding(.vertical, 8)
                .background(Color(nsColor: .controlBackgroundColor))
                .transition(reduceMotion ? .opacity : .move(edge: .bottom))
            }
        }
        .task {
            await appState.loadAlerts()
        }
    }

    // MARK: - Toast & Undo

    /// Monotonic token that invalidates the auto-dismiss timer of a prior toast
    /// when a new toast is shown. Without this, a fast double-suppress fires two
    /// 5 s timers; the first closes the second toast early.
    @State private var toastGeneration: Int = 0

    /// Show the suppression toast. `ids` are the alert IDs that Undo will
    /// revert. Empty `ids` hides the Undo button (pure "info" toast).
    private func presentSuppressToast(names: [String], ids: [String]) {
        suppressedAlertName = names.count <= 1
            ? (names.first ?? "")
            : String(localized: "alerts.suppressedCount", defaultValue: "\(names.count) alerts")
        undoAlertIDs = ids
        showUndoToast = true
        toastGeneration &+= 1
        let gen = toastGeneration
        DispatchQueue.main.asyncAfter(deadline: .now() + 5) {
            if gen == toastGeneration {
                dismissSuppressToast()
            }
        }
    }

    private func dismissSuppressToast() {
        showUndoToast = false
        suppressedAlertName = nil
        undoAlertIDs = []
    }

    /// Undo the most recent suppression (single or bulk). Safe to call repeatedly.
    private func undoLastSuppress() {
        let ids = undoAlertIDs
        guard !ids.isEmpty else { return }
        dismissSuppressToast()
        Task {
            for id in ids {
                await appState.unsuppressAlert(id)
            }
        }
    }

    // MARK: - Bulk Actions

    private func bulkSuppress() {
        let alertsToSuppress = Array(selectedAlerts)
        let ids = alertsToSuppress.map(\.id)
        let names = alertsToSuppress.map(\.ruleTitle)
        selectedAlerts = []
        Task {
            for alert in alertsToSuppress {
                await appState.suppressAlert(alert.id)
            }
        }
        presentSuppressToast(names: names, ids: ids)
    }

    private func bulkUnsuppress() {
        let alertsToUnsuppress = selectedAlerts.filter { $0.suppressed }
        let count = alertsToUnsuppress.count
        selectedAlerts = []
        Task {
            for alert in alertsToUnsuppress {
                await appState.unsuppressAlert(alert.id)
            }
        }
        // Info-only toast (no Undo — undoing an unsuppress would re-suppress, confusing).
        suppressedAlertName = String(localized: "alerts.unsuppressedCount", defaultValue: "Unsuppressed \(count) alerts")
        undoAlertIDs = []
        showUndoToast = true
        toastGeneration &+= 1
        let gen = toastGeneration
        DispatchQueue.main.asyncAfter(deadline: .now() + 3) {
            if gen == toastGeneration {
                dismissSuppressToast()
            }
        }
    }

    // MARK: - Export Functions

    private func exportAlerts(format: AlertExporter.ExportFormat) {
        exportInProgress = true
        Task {
            let exporter = AlertExporter()
            let exportable = filteredAlerts.map { alert in
                AlertExporter.ExportableAlert(
                    id: alert.id,
                    timestamp: alert.timestamp,
                    ruleId: alert.id, // Use alert id as ruleId fallback
                    ruleTitle: alert.ruleTitle,
                    severity: alert.severity.rawValue,
                    processName: alert.processName,
                    processPath: alert.processPath,
                    description: alert.description,
                    mitreTactics: "",
                    mitreTechniques: alert.mitreTechniques
                )
            }
            let content = await exporter.export(alerts: exportable, format: format)
            let ext = format.fileExtension

            await MainActor.run {
                let panel = NSSavePanel()
                panel.title = "Export Alerts"
                panel.nameFieldStringValue = "maccrab-alerts.\(ext)"
                panel.allowedContentTypes = [.data]
                panel.canCreateDirectories = true

                if panel.runModal() == .OK, let url = panel.url {
                    try? content.write(to: url, atomically: true, encoding: .utf8)
                }
                exportInProgress = false
            }
        }
    }

    private func exportHTMLReport() {
        exportInProgress = true
        Task {
            let generator = ReportGenerator()
            let alertData = filteredAlerts.map { alert in
                Alert(
                    id: alert.id,
                    timestamp: alert.timestamp,
                    ruleId: alert.id,
                    ruleTitle: alert.ruleTitle,
                    severity: MacCrabCore.Severity(rawValue: alert.severity.rawValue) ?? .medium,
                    eventId: UUID().uuidString,
                    processPath: alert.processPath,
                    processName: alert.processName,
                    description: alert.description,
                    mitreTechniques: alert.mitreTechniques
                )
            }
            let reportData = await generator.buildReportData(alerts: alertData)
            let html = await generator.generateHTML(from: reportData)

            await MainActor.run {
                let panel = NSSavePanel()
                panel.title = "Export HTML Report"
                panel.nameFieldStringValue = "maccrab-report.html"
                panel.allowedContentTypes = [.html]
                panel.canCreateDirectories = true

                if panel.runModal() == .OK, let url = panel.url {
                    try? html.write(to: url, atomically: true, encoding: .utf8)
                }
                exportInProgress = false
            }
        }
    }
}

// MARK: - Alert Detail View

struct AlertDetailView: View {
    let alert: AlertViewModel
    var appState: AppState? = nil
    let onSuppress: () -> Void
    var onUnsuppress: (() -> Void)? = nil
    var onSuppressPattern: (() -> Void)? = nil

    @State private var showKillConfirm = false
    @State private var showQuarantineConfirm = false
    @State private var showBlockConfirm = false
    @State private var actionFeedback: String?
    @State private var triggerEvent: Event?

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                // Severity + Time header
                HStack {
                    HStack(spacing: 6) {
                        Image(systemName: alert.severity.sfSymbol)
                            .font(.caption)
                            .foregroundColor(alert.severityColor)
                            .accessibilityHidden(true)
                        Text(RuleTranslations.translateSeverity(alert.severity.label)).font(.caption).fontWeight(.bold).foregroundColor(alert.severityColor)
                    }
                    .padding(.horizontal, 8).padding(.vertical, 3)
                    .background(alert.severityColor.opacity(0.1))
                    .clipShape(Capsule())

                    // Show configured response action badge if applicable
                    if Self.hasConfiguredAction(for: alert) {
                        HStack(spacing: 4) {
                            Image(systemName: "bolt.shield.fill")
                                .font(.caption2)
                                .accessibilityHidden(true)
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

                // Triggering event — fetched from the event store using
                // alert.eventId. Shows the fields that actually matter for
                // triage: what the process ran (command line), who launched
                // it (parent chain), what file/network endpoint it touched,
                // and how it was signed.
                if let event = triggerEvent {
                    GroupBox("Triggering Event") {
                        VStack(alignment: .leading, spacing: 6) {
                            DetailRow(label: "Action", value: "\(event.eventCategory.rawValue) / \(event.eventAction)")
                            if !event.process.commandLine.isEmpty {
                                DetailRow(label: "Command Line", value: event.process.commandLine)
                            }
                            DetailRow(label: "PID", value: "\(event.process.pid)")
                            if let sig = event.process.codeSignature {
                                DetailRow(label: "Signer", value: sig.signerType.rawValue + (sig.teamId.map { " (team \($0))" } ?? ""))
                            }
                            if let parent = event.process.ancestors.first {
                                DetailRow(label: "Parent", value: "\(parent.name) — \(parent.executable)")
                            }
                            if event.process.ancestors.count > 1 {
                                let chain = event.process.ancestors.prefix(5).reversed().map(\.name).joined(separator: " → ")
                                DetailRow(label: "Ancestry", value: chain + " → " + event.process.name)
                            }
                            if let file = event.file {
                                DetailRow(label: "File", value: file.path)
                                if let src = file.sourcePath { DetailRow(label: "Source Path", value: src) }
                            }
                            if let net = event.network {
                                let hostOrIp = net.destinationHostname ?? net.destinationIp
                                let shown = hostOrIp.isEmpty ? "unresolved" : hostOrIp
                                DetailRow(label: "Destination", value: "\(shown):\(net.destinationPort) (\(net.transport))")
                            }
                            if let tcc = event.tcc {
                                DetailRow(label: "TCC Service", value: tcc.service)
                                DetailRow(label: "TCC Allowed", value: tcc.allowed ? "yes" : "no")
                            }
                        }.padding(4)
                    }
                }

                // MITRE ATT&CK
                if !alert.mitreTechniques.isEmpty {
                    GroupBox(String(localized: "alertDetail.mitreAttack", defaultValue: "MITRE ATT&CK")) {
                        VStack(alignment: .leading, spacing: 6) {
                            let techniques = alert.mitreTechniques.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
                            ForEach(techniques, id: \.self) { tech in
                                HStack {
                                    Image(systemName: "shield.fill").foregroundColor(.orange).font(.caption)
                                        .accessibilityHidden(true)
                                    Text(tech).font(.system(.body, design: .monospaced))
                                    Spacer()
                                    Link("View", destination: URL(string: "https://attack.mitre.org/techniques/\(tech.replacingOccurrences(of: "attack.", with: "").uppercased().replacingOccurrences(of: ".", with: "/"))/")!)
                                        .font(.caption)
                                }
                            }
                        }.padding(4)
                    }
                }

                // Phase 4: structured LLM investigation (when available).
                // Only renders if the daemon has run LLMService.investigate()
                // against this alert and persisted the result.
                if let investigation = alert.llmInvestigation {
                    InvestigationSection(investigation: investigation)
                }

                // What to do — actionable guidance based on alert context
                GroupBox(String(localized: "alertDetail.whatToDo", defaultValue: "What To Do")) {
                    VStack(alignment: .leading, spacing: 8) {
                        ForEach(Array(alertGuidance(alert).enumerated()), id: \.offset) { _, item in
                            HStack(alignment: .top, spacing: 8) {
                                Image(systemName: item.icon)
                                    .font(.caption)
                                    .foregroundColor(.accentColor)
                                    .frame(width: 16)
                                    .accessibilityHidden(true)
                                Text(item.text)
                                    .font(.callout)
                                    .foregroundColor(.primary)
                            }
                        }
                    }
                    .padding(4)
                }

                // Alert metadata
                GroupBox(String(localized: "alertDetail.metadata", defaultValue: "Metadata")) {
                    VStack(alignment: .leading, spacing: 6) {
                        DetailRow(label: String(localized: "alertDetail.alertId", defaultValue: "Alert ID"), value: alert.id)
                        DetailRow(label: String(localized: "alertDetail.severity", defaultValue: "Severity"), value: RuleTranslations.translateSeverity(alert.severity.label))
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
                                .help(String(
                                    localized: "action.suppressAll.hint",
                                    defaultValue: "Suppress all alerts matching '\(alert.ruleTitle)' from '\(alert.processName)'"
                                ))
                            } else {
                                Button { onUnsuppress?() } label: {
                                    Label(String(localized: "action.unsuppress", defaultValue: "Unsuppress"), systemImage: "eye")
                                }.controlSize(.large)
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
                                .help(String(
                                    localized: "action.kill.hint",
                                    defaultValue: "Terminate \(alert.processName)"
                                ))
                                .confirmationDialog(
                                    "\(String(localized: "action.kill", defaultValue: "Kill Process")) — \(alert.processName)?",
                                    isPresented: $showKillConfirm,
                                    titleVisibility: .visible
                                ) {
                                    Button(String(localized: "action.kill", defaultValue: "Kill Process"), role: .destructive) {
                                        do {
                                            let msg = try ManualResponse.killProcess(
                                                pid: nil,
                                                path: alert.processPath
                                            )
                                            actionFeedback = msg
                                        } catch {
                                            actionFeedback = (error as? ManualResponse.ActionError)
                                                .map(\.description) ?? error.localizedDescription
                                        }
                                    }
                                } message: {
                                    Text(String(
                                        localized: "action.kill.message",
                                        defaultValue: "This will terminate \(alert.processName) at \(alert.processPath). This action cannot be undone."
                                    ))
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
                                        do {
                                            let msg = try ManualResponse.quarantineFile(
                                                path: alert.processPath,
                                                ruleId: alert.ruleId,
                                                ruleTitle: alert.ruleTitle,
                                                alertId: alert.id
                                            )
                                            actionFeedback = msg
                                        } catch {
                                            actionFeedback = (error as? ManualResponse.ActionError)
                                                .map(\.description) ?? error.localizedDescription
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
                                        guard let ip = Self.extractIP(from: alert.description) else {
                                            actionFeedback = "No IP found in alert description"
                                            return
                                        }
                                        do {
                                            let msg = try ManualResponse.blockDestination(ip: ip)
                                            actionFeedback = msg
                                        } catch {
                                            actionFeedback = (error as? ManualResponse.ActionError)
                                                .map(\.description) ?? error.localizedDescription
                                        }
                                    }
                                } message: {
                                    Text(String(
                                        localized: "action.block.message",
                                        defaultValue: "This will block the network destination associated with \(alert.processName). Applications will no longer be able to reach this endpoint."
                                    ))
                                }
                            }

                            // Copy details always available — plain text for
                            // quick paste into terminal / email / SIEM.
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
                                actionFeedback = String(localized: "action.copyDetails.done", defaultValue: "Copied details")
                            } label: {
                                Label(String(localized: "action.copyDetails", defaultValue: "Copy Details"), systemImage: "doc.on.doc")
                            }
                            .controlSize(.large)
                            .accessibilityHint(String(
                                localized: "action.copyDetails.hint",
                                defaultValue: "Copies alert details to clipboard"
                            ))

                            // Copy as Markdown — for pasting into tickets,
                            // PRs, Slack, incident reports. Different from
                            // plain text: wraps values in code spans,
                            // bolds severity, formats MITRE as a list.
                            Button {
                                NSPasteboard.general.clearContents()
                                NSPasteboard.general.setString(
                                    markdownSummary(for: alert),
                                    forType: .string
                                )
                                actionFeedback = String(localized: "action.copyMarkdown.done", defaultValue: "Copied as Markdown")
                            } label: {
                                Label(String(localized: "action.copyMarkdown", defaultValue: "Copy as Markdown"), systemImage: "text.badge.plus")
                            }
                            .controlSize(.large)
                            .help(String(localized: "action.copyMarkdown.hint", defaultValue: "Copy as Markdown for pasting into tickets or Slack"))
                        }

                        if let feedback = actionFeedback {
                            HStack {
                                Image(systemName: "checkmark.circle.fill")
                                    .foregroundColor(.green)
                                    .accessibilityHidden(true)
                                Text(feedback)
                                    .font(.caption)
                                    .foregroundColor(.secondary)
                            }
                        }
                    }.padding(4)
                }

                Spacer()
            }.padding()
        }
        .background(Color(nsColor: .controlBackgroundColor))
        .task(id: alert.id) {
            // Fetch the underlying event for the detail GroupBox. Runs
            // on every selection change (task(id:) re-runs when id
            // changes) so switching alerts reloads the correct event.
            // Skip for alerts without an eventId (USB / clipboard /
            // tamper — they have no backing Event).
            guard !alert.eventId.isEmpty, let state = appState else {
                triggerEvent = nil
                return
            }
            triggerEvent = await state.fetchEvent(id: alert.eventId)
        }
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

    /// Format an alert as Markdown suitable for pasting into a ticket,
    /// Slack message, or incident report. Separate from plain-text
    /// "Copy Details" because the rendering target is different (terminals
    /// vs markdown-rendered surfaces).
    fileprivate func markdownSummary(for alert: AlertViewModel) -> String {
        var lines: [String] = []
        lines.append("## \(alert.ruleTitle)")
        lines.append("")
        lines.append("- **Severity:** \(alert.severity.label)")
        lines.append("- **Time:** \(alert.dateTimeString)")
        if !alert.processName.isEmpty {
            lines.append("- **Process:** `\(alert.processName)`")
        }
        if !alert.processPath.isEmpty {
            lines.append("- **Process path:** `\(alert.processPath)`")
        }
        lines.append("- **Rule ID:** `\(alert.ruleId)`")
        lines.append("- **Alert ID:** `\(alert.id)`")
        let techniques = alert.mitreTechniques
            .split(separator: ",")
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
        if !techniques.isEmpty {
            lines.append("- **MITRE ATT&CK:** " + techniques.map { "[\($0)](https://attack.mitre.org/techniques/\($0.uppercased())/)" }.joined(separator: ", "))
        }
        if !alert.description.isEmpty {
            lines.append("")
            lines.append("### Description")
            lines.append("")
            lines.append(alert.description)
        }
        lines.append("")
        lines.append("*Generated by MacCrab*")
        return lines.joined(separator: "\n")
    }

    /// Pull the first IPv4 or IPv6 address out of an alert description so the
    /// Block Destination button has something to hand to pfctl. If nothing
    /// plausible matches, returns nil and the UI shows "No IP found".
    fileprivate static func extractIP(from text: String) -> String? {
        // IPv4 first — anchored on word boundaries, each octet 0-255.
        let v4 = #"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"#
        if let match = text.range(of: v4, options: .regularExpression) {
            return String(text[match])
        }
        // IPv6 — loose match; inet_pton in ManualResponse rejects non-IPs.
        let v6 = #"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b"#
        if let match = text.range(of: v6, options: .regularExpression) {
            return String(text[match])
        }
        return nil
    }
}


/// Generate actionable guidance for an alert based on its MITRE techniques,
/// severity, and rule metadata.
func alertGuidance(_ alert: AlertViewModel) -> [(icon: String, text: String)] {
    var items: [(String, String)] = []
    let techniques = alert.mitreTechniques.lowercased()
    let ruleId = alert.ruleId.lowercased()

    // Severity-based urgency
    if alert.severity == .critical {
        items.append(("exclamationmark.triangle.fill", "Investigate immediately — this is a critical severity detection."))
    }

    // Persistence
    if techniques.contains("t1543") || techniques.contains("t1546") || ruleId.contains("launchagent") || ruleId.contains("persistence") {
        items.append(("trash", "Check ~/Library/LaunchAgents/ and /Library/LaunchDaemons/ for unfamiliar entries. Remove any you don't recognize."))
        items.append(("arrow.clockwise", "Run: launchctl list | grep -v com.apple to see active non-Apple services."))
    }

    // Credential access
    if techniques.contains("t1555") || techniques.contains("t1552") || ruleId.contains("credential") || ruleId.contains("keychain") || ruleId.contains("ssh_key") {
        items.append(("key", "Rotate any credentials that may have been accessed (passwords, SSH keys, API tokens)."))
        items.append(("lock.shield", "Check Keychain Access.app for recently added or modified entries."))
    }

    // C2 / beacon
    if techniques.contains("t1071") || techniques.contains("t1095") || ruleId.contains("beacon") || ruleId.contains("c2") {
        items.append(("network.badge.shield.half.filled", "Check if the destination IP/domain is known-malicious using VirusTotal or AbuseIPDB."))
        items.append(("hand.raised", "If confirmed malicious, enable Prevention > Network Blocker to block the IP."))
    }

    // Defense evasion / quarantine
    if techniques.contains("t1553") || ruleId.contains("quarantine") || ruleId.contains("gatekeeper") {
        items.append(("checkmark.shield", "Re-apply quarantine: xattr -w com.apple.quarantine '0081' <file>"))
        items.append(("magnifyingglass", "Verify the file's code signature: codesign -dvvv <path>"))
    }

    // AI tool
    if ruleId.contains("ai-guard") || ruleId.contains("ai_tool") || ruleId.contains("prompt") || ruleId.contains("boundary") {
        items.append(("brain", "Review what the AI tool accessed — check the process path and parent."))
        items.append(("arrow.counterclockwise", "Restart the AI tool session to clear any potentially injected context."))
    }

    // Behavioral score
    if ruleId.contains("behavioral") || ruleId.contains("behavior") {
        items.append(("chart.line.uptrend.xyaxis", "This process accumulated multiple suspicious indicators. Review its full activity in the Events tab."))
        items.append(("xmark.circle", "If the process is unfamiliar, terminate it: kill -9 <PID>"))
    }

    // Rootkit
    if techniques.contains("t1014") || ruleId.contains("rootkit") || ruleId.contains("hidden_process") {
        items.append(("exclamationmark.shield", "A hidden process was detected. This may indicate kernel-level compromise."))
        items.append(("power", "Consider a clean reboot and running a full system scan."))
    }

    // Generic fallback
    if items.isEmpty || (items.count == 1 && alert.severity == .critical) {
        if !alert.processPath.isEmpty {
            items.append(("magnifyingglass", "Investigate the process: ls -la \(alert.processPath)"))
            items.append(("terminal", "Check process lineage: maccrabctl tree-score"))
        }
        items.append(("eye.slash", "If this is expected behavior, suppress this alert to reduce noise."))
    }

    return items
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
