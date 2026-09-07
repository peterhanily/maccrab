// V2AlertsWorkspace.swift
// Spec §7.2 — triage, route, and dispose alerts. Severity summary
// + alerts table + selectable inspector with verbs.

import SwiftUI
import AppKit
import UniformTypeIdentifiers
import MacCrabCore

struct V2AlertsWorkspace: View {
    // v1.11.1 (audit perf LOW): hoisted formatter for the JSON-export
    // path so we don't pay ~0.5 ms per alert row to instantiate one.
    nonisolated(unsafe) static let isoFormatter = ISO8601DateFormatter()

    @ObservedObject var state: V2DashboardState
    @ObservedObject var appState: AppState
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var selected: V2MockAlert?
    @State private var suppressionEntries: [V2SuppressionEntry] = []
    @State private var alerts: [V2MockAlert] = []
    @State private var campaigns: [V2MockCampaign] = []
    @State private var suppressedCampaigns: [V2MockCampaign] = []
    @State private var selectedCampaignIds: Set<String> = []
    // v1.21.4: multi-select set for the Open table's checkbox column. When
    // non-empty, Bulk suppress targets the checked subset instead of every
    // visible row.
    @State private var selectedAlertIds: Set<String> = []
    @State private var loaded = false
    // Requests are displayed separately from stored alert/campaign state.
    // An accepted inbox request must never hide or rewrite a committed row.
    @State private var mutations = V2MutationTracker()
    @StateObject private var mutationConfirmation = V2MutationConfirmationLoop()
    @State private var mutationProviderID: ObjectIdentifier?
    @State private var lastUndoBatch: [V2MutationRequest] = []
    @State private var showAllMutationDetails = false
    // Destructive/large-batch confirmations. A permanent delete and a bulk
    // suppress that can hit the full visible set (fetch cap 1000) both warrant
    // a confirm step — matching the Forensics bulk-delete precedent.
    @State private var pendingDeleteAlert: V2MockAlert?
    @State private var pendingBulkSuppress: [V2MockAlert]?

    /// Bulk suppress runs immediately at or below this count; above it, a
    /// confirmation dialog gates the action.
    private let bulkSuppressConfirmThreshold = 5

    init(state: V2DashboardState, appState: AppState) {
        self.state = state
        self.appState = appState
    }

    /// Bind to the workspace-state-owned filter so a navigation
    /// pivot away and back preserves the user's narrowing.
    private var severityFilter: Binding<V2Severity?> {
        Binding(get: { state.alertSeverityFilter },
                set: { state.alertSeverityFilter = $0 })
    }
    private var query: Binding<String> {
        Binding(get: { state.alertSearchQuery },
                set: { state.alertSearchQuery = $0 })
    }
    /// Stable key for the reload `.task(id:)` so a new histogram-window
    /// (D7) triggers a re-fetch bounded to that window; empty when none.
    private var windowTaskKey: String {
        guard let w = state.pendingAlertsWindow else { return "" }
        return "\(Int(w.start.timeIntervalSince1970))-\(Int(w.end.timeIntervalSince1970))"
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            V2WorkspaceTabStrip(
                tabs: V2Workspace.alerts.tabs,
                selected: Binding(
                    get: { state.selectedTabs[.alerts] ?? .alertsOpen },
                    // Route through selectTab → goto so the tab switch is
                    // pushed onto history, recorded as a recent, and persisted.
                    // Writing selectedTabs directly bypassed all three, which is
                    // why ⌘[ from a tab jumped to a different workspace and tab
                    // selection didn't survive quit.
                    set: { if let v = $0 { state.selectTab(v) } }
                )
            )
            if !mutations.entries.isEmpty { mutationStatusBanner }
            tabBody
                .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
        .task(id: "\(state.provider.mode):\(state.refreshTick):\(state.alertTimeRange):\(windowTaskKey)") { await reload() }
        // Table refresh cancellation must not starve saved-state confirmation.
        // SwiftUI cancels this task when its provider changes or the view leaves.
        .task(id: ObjectIdentifier(state.provider)) { await confirmMutations() }
        // Permanent-delete confirmation (History tab). The delete is a hard
        // DELETE FROM alerts with no undo — including the snapshotted
        // triggering-event evidence — so it must not fire on a single mis-click.
        .confirmationDialog(
            String(localized: "alerts.confirmDeleteTitle", defaultValue: "Delete this alert permanently?"),
            isPresented: Binding(get: { pendingDeleteAlert != nil },
                                 set: { if !$0 { pendingDeleteAlert = nil } }),
            presenting: pendingDeleteAlert
        ) { alert in
            Button(role: .destructive) {
                let target = alert
                pendingDeleteAlert = nil
                Task { await deleteAlert(target) }
            } label: { Text(String(localized: "alerts.confirmDeleteButton", defaultValue: "Delete")) }
            Button(role: .cancel) { pendingDeleteAlert = nil } label: {
                Text(String(localized: "common.cancel", defaultValue: "Cancel"))
            }
        } message: { alert in
            Text(String(localized: "alerts.confirmDeleteMessage",
                        defaultValue: "“\(alert.title)” and its snapshotted evidence will be permanently removed from alerts.db. This cannot be undone."))
        }
        // Large bulk-suppress confirmation. Bulk suppress can target the full
        // visible set (fetch cap 1000); a confirm step above a small threshold
        // guards against silencing far more than intended.
        .confirmationDialog(
            String(localized: "alerts.confirmBulkSuppressTitle", defaultValue: "Suppress these alerts?"),
            isPresented: Binding(get: { pendingBulkSuppress != nil },
                                 set: { if !$0 { pendingBulkSuppress = nil } }),
            presenting: pendingBulkSuppress
        ) { targets in
            Button {
                let batch = targets
                pendingBulkSuppress = nil
                Task { await bulkSuppress(batch) }
            } label: {
                Text(String(localized: "alerts.confirmBulkSuppressButton",
                            defaultValue: "Suppress \(targets.count)"))
            }
            Button(role: .cancel) { pendingBulkSuppress = nil } label: {
                Text(String(localized: "common.cancel", defaultValue: "Cancel"))
            }
        } message: { targets in
            Text(String(localized: "alerts.confirmBulkSuppressMessage",
                        defaultValue: "\(targets.count) alerts currently visible will be suppressed. You can lift suppressions from the History and Suppressions tabs."))
        }
    }

    private var mutationStatusBanner: some View {
        VStack(alignment: .leading, spacing: 7) {
            HStack {
                Text(String(localized: "mutation.statusTitle", defaultValue: "Requested changes"))
                    .font(V2Theme.cardTitle())
                Spacer()
                if mutations.entries.count > 3 {
                    Button(showAllMutationDetails
                           ? String(localized: "mutation.showLess", defaultValue: "Show less")
                           : String(localized: "mutation.showAll", defaultValue: "Show all requests")) {
                        showAllMutationDetails.toggle()
                    }
                    .buttonStyle(.plain)
                }
                if mutations.allApplied(lastUndoBatch) {
                    Button(String(localized: "mutation.undoBulk", defaultValue: "Undo bulk suppression")) {
                        let requests = lastUndoBatch.map {
                            V2MutationRequest(operation: .unsuppressAlert, targetID: $0.targetID, title: $0.title)
                        }
                        lastUndoBatch = []
                        Task { await submitMutations(requests) }
                    }
                    .buttonStyle(.plain)
                }
                Button(String(localized: "mutation.dismissCompleted", defaultValue: "Dismiss completed")) {
                    mutations.dismissCompleted()
                    lastUndoBatch = []
                }
                .buttonStyle(.plain)
            }
            Text(String(localized: "mutation.pendingDetail", defaultValue: "\(mutations.pending.count) requests pending. Rows show saved state until the engine confirms each change."))
                .font(V2Theme.meta()).foregroundStyle(V2Theme.mutedText)
            if showAllMutationDetails {
                ScrollView {
                    LazyVStack(spacing: 7) {
                        ForEach(Array(mutations.entries.reversed())) { entry in mutationStatusRow(entry) }
                    }
                }
                .frame(maxHeight: 180)
            } else {
                ForEach(Array(mutations.entries.suffix(3))) { entry in mutationStatusRow(entry) }
            }
        }
        .foregroundStyle(V2Theme.primaryText)
        .padding(12)
        .background(V2Theme.panelBackground)
    }

    private func mutationStatusRow(_ entry: V2MutationTracker.Entry) -> some View {
        HStack(alignment: .top, spacing: 8) {
            VStack(alignment: .leading, spacing: 2) {
                Text("\(entry.request.operation.label): \(entry.request.title)")
                    .font(V2Theme.meta()).lineLimit(2)
                if case .failed(let detail) = entry.status {
                    Text(detail).font(V2Theme.meta()).foregroundStyle(V2Theme.warning)
                        .lineLimit(2).help(detail)
                }
            }
            Spacer()
            V2StatusChip(entry.status.label, kind: entry.status.chipKind)
        }
    }

    @MainActor
    private func syncMutationProvider() {
        let current = ObjectIdentifier(state.provider)
        if let mutationProviderID, mutationProviderID != current {
            mutations.invalidatePending()
            lastUndoBatch = []
        }
        mutationProviderID = current
    }

    @MainActor
    private func submitMutations(_ requests: [V2MutationRequest]) async {
        guard !requests.isEmpty else { return }
        syncMutationProvider()
        let provider = state.provider
        var sent = 0
        for request in requests {
            guard ObjectIdentifier(state.provider) == ObjectIdentifier(provider) else {
                syncMutationProvider()
                break
            }
            guard mutations.begin(request) else { continue }
            let result = await provider.submitMutation(request)
            mutations.submitted(request, result: result)
            if result == .queued || result == .applied { sent += 1 }
        }
        state.showToast(V2Toast(
            kind: sent == requests.count ? .info : .warning,
            title: sent > 0
                ? String(localized: "mutation.requestedTitle", defaultValue: "Changes requested")
                : String(localized: "mutation.notSentTitle", defaultValue: "No new requests sent"),
            detail: String(localized: "mutation.requestedDetail", defaultValue: "\(sent) of \(requests.count) requests accepted. Review Requested changes for confirmation; saved rows remain visible.")))
        // The independent confirmation loop observes saved state. Table rows
        // refresh on their normal cadence; submission starts no trailing reads.
    }

    @MainActor
    private func confirmMutations() async {
        syncMutationProvider()
        let provider = state.provider
        await mutationConfirmation.run(nextBatch: {
            syncMutationProvider()
            mutations.expire()
            guard ObjectIdentifier(state.provider) == ObjectIdentifier(provider) else { return [] }
            return mutations.confirmationBatch.map(\.request)
        }, confirm: { request in
            await provider.confirmMutation(request)
        }, observed: { request, confirmation in
            guard ObjectIdentifier(state.provider) == ObjectIdentifier(provider) else {
                syncMutationProvider()
                return
            }
            mutations.observed(request, confirmation: confirmation)
        })
    }

    private func reload() async {
        await MainActor.run {
            syncMutationProvider()
            mutations.expire()
        }
        // v1.12.6 Wave 9P: write each piece of @State as soon as it
        // resolves, rather than batching all three into one trailing
        // MainActor.run. Pre-9P, on a host with a big alerts.db /
        // campaigns.db, the three sequential awaits could exceed the
        // 5s auto-refresh-tick interval. When `state.refreshTick`
        // incremented, SwiftUI's `.task(id:)` cancelled the running
        // reload before the final MainActor.run ever fired —
        // permanent staleness until the user closed and reopened the
        // dashboard (which reset refreshTick to 0 and gave the body
        // an uncontested first load). Same root cause as Wave 9G,
        // just in three more workspaces. The cutoff calculation +
        // filtering stays inside MainActor.run so the filtered
        // arrays don't get computed against the wrong state.
        let cutoff: Date = {
            switch state.alertTimeRange {
            case "24h": return Date().addingTimeInterval(-86_400)
            case "7d":  return Date().addingTimeInterval(-7 * 86_400)
            case "30d": return Date().addingTimeInterval(-30 * 86_400)
            default:    return Date.distantPast
            }
        }()

        // D7: an Overview histogram bar tap constrains the Open list to a
        // single [start, end] bucket. When present it overrides the range
        // chip's lower bound (fetch `since:` its start) and adds an upper
        // bound (filtered below). Persists until the user picks a chip or
        // clears the banner, so it survives the 5 s refresh reload.
        let window = state.pendingAlertsWindow
        let lowerBound = window?.start ?? cutoff

        // Wide ranges need a higher ceiling than the default 200 so All-time
        // doesn't silently truncate the history the chip just unlocked. A
        // window is a tight bucket, so the default 200 is ample there.
        let fetchLimit = (window != nil || state.alertTimeRange == "24h" || state.alertTimeRange == "7d") ? 200 : 1000
        let a = await state.provider.alerts(since: lowerBound, limit: fetchLimit)
        await MainActor.run {
            self.alerts = a.filter { alert in
                // D7: bound below by the range cutoff (or window start) and,
                // when a histogram window is active, above by its end.
                alert.timestamp >= lowerBound
                    && (window.map { alert.timestamp <= $0.end } ?? true)
            }
            // Reconcile the floating inspector against the fresh data:
            // drop the selection if its row is gone (deleted, or aged
            // past the time-range cutoff), otherwise refresh it to the
            // new snapshot so the inspector never shows a stale,
            // pre-mutation copy.
            if let sel = self.selected {
                self.selected = self.alerts.first(where: { $0.id == sel.id })
            }
            self.loaded = true
        }

        let c = await state.provider.campaigns(since: cutoff, limit: 50)
        await MainActor.run {
            self.campaigns = c.filter { $0.lastSeen >= cutoff }
        }

        // Suppressed campaigns — powers the in-UI restore surface.
        let sc = await state.provider.suppressedCampaigns(limit: 50)
        await MainActor.run { self.suppressedCampaigns = sc }

        let s = await state.provider.suppressions()
        await MainActor.run {
            self.suppressionEntries = s
            // If the navigation destination requested a specific alert
            // (notification "View" button or palette entity link), select
            // it now that we have the data. entityKey format matches
            // V2DashboardState.entityKey: "<workspace>:<tab>" or just
            // "<workspace>".
            let candidateKeys = ["alerts:alertsOpen", "alerts"]
            for key in candidateKeys {
                if let pendingId = state.selectedEntities[key],
                   let match = a.first(where: { $0.id == pendingId }) {
                    self.selected = match
                    state.selectedEntities[key] = nil
                    break
                }
            }
        }
    }

    // MARK: - Mutations

    private func suppress(_ alert: V2MockAlert) async {
        await submitMutations([.init(operation: .suppressAlert, targetID: alert.id, title: alert.title)])
    }

    private var campaignsToolbar: some View {
        HStack(spacing: 8) {
            Button {
                if selectedCampaignIds.count == campaigns.count {
                    selectedCampaignIds.removeAll()
                } else {
                    selectedCampaignIds = Set(campaigns.map(\.id))
                }
            } label: {
                let allSelected = selectedCampaignIds.count == campaigns.count
                Image(systemName: allSelected ? "checkmark.square.fill" : "square")
                    .foregroundStyle(allSelected ? V2Theme.brand : V2Theme.mutedText)
                    .scaledSystem(14)
            }
            .buttonStyle(.plain)
            .help(selectedCampaignIds.count == campaigns.count ? "Deselect all" : "Select all campaigns")

            if selectedCampaignIds.isEmpty {
                Text(String(localized: "ui.final.campaignCount", defaultValue: "Campaigns: \(campaigns.count) · click to select for bulk suppression"))
                    .font(V2Theme.meta())
                    .foregroundStyle(V2Theme.mutedText)
            } else {
                Text(String(localized: "ui.final.selectedCampaignCount", defaultValue: "\(selectedCampaignIds.count) of \(campaigns.count) selected"))
                    .font(V2Theme.meta())
                    .foregroundStyle(V2Theme.primaryText)
            }
            Spacer()
            V2ActionButton(String(localized: "ui.V2AlertsWorkspace.bulk.suppress", defaultValue: "Bulk suppress (\(selectedCampaignIds.count))"),
                           icon: "bell.slash",
                           style: selectedCampaignIds.isEmpty ? .ghost : .primary,
                           disabled: selectedCampaignIds.isEmpty,
                           tooltip: selectedCampaignIds.isEmpty
                                    ? "Select one or more campaigns first"
                                    : "Suppress selected campaigns and their contributing alerts") {
                let targets = campaigns.filter { selectedCampaignIds.contains($0.id) }
                Task { await bulkSuppressCampaigns(targets) }
            }
        }
        .padding(10)
        .background(V2Theme.panelBackground)
        .clipShape(RoundedRectangle(cornerRadius: V2Theme.smallCornerRadius))
    }

    private func bulkSuppressCampaigns(_ targets: [V2MockCampaign]) async {
        await MainActor.run { selectedCampaignIds.removeAll() }
        await submitMutations(targets.map {
            .init(operation: .suppressCampaign, targetID: $0.id, title: $0.name)
        })
    }

    /// Layout helper: render a list of strings as wrapped chips. Each
    /// chip is a click target — tap fires the callback.
    @ViewBuilder
    private func FlowingChips(items: [String], kind: V2ChipKind, onTap: @escaping (String) -> Void) -> some View {
        // The inspector pane is a fixed ~340 pt and a plain HStack doesn't
        // wrap — extra chips clipped off the right edge and became
        // unreachable. A horizontal ScrollView keeps every chip on one
        // scannable, scrollable line (the same pattern `campaignChipRow` uses).
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 6) {
                ForEach(items, id: \.self) { tech in
                    Button { onTap(tech) } label: {
                        V2StatusChip(tech, kind: kind, icon: "arrow.up.forward")
                    }
                    .buttonStyle(.plain)
                    .help(String(localized: "ui.V2AlertsWorkspace.open.mitre.d3fend.reference.for", defaultValue: "Open MITRE D3FEND reference for \(tech)"))
                }
            }
        }
    }

    /// Map LLM verdict raw value → chip color. Used in the AI analysis
    /// section to give analysts a fast visual cue.
    private func verdictChipKind(_ v: String) -> V2ChipKind {
        switch v {
        case "true_positive":  return .high
        case "benign":         return .healthy
        case "needs_human":    return .warning
        case "uncertain":      return .info
        default:               return .neutral
        }
    }

    /// Deterministic, LLM-free triage guidance shown in "What to do" when the
    /// alert has no persisted remediation hint.
    private func defaultRemediation(for alert: V2MockAlert) -> String {
        var lines: [String] = []
        if alert.severity == .critical || alert.severity == .high {
            lines.append("Treat this as high priority. Review the process, path, and parent above to decide whether this activity is expected on this Mac.")
        } else {
            lines.append("Review the process, path, and parent above to decide whether this activity is expected on this Mac.")
        }
        lines.append("Use “Investigate in Events” to see what happened around the time it fired, and open the full causal trace with the CLI command in Trace context below.")
        lines.append("If it’s expected, suppress the alert so it stops recurring. If it isn’t, isolate the process and preserve evidence before acting.")
        return lines.joined(separator: "\n\n")
    }

    /// True when the alert carries any analyst-workflow metadata worth showing.
    private func hasAnalystMetadata(_ a: V2MockAlert) -> Bool {
        (a.analystStatus?.isEmpty == false)
            || (a.analystOwner?.isEmpty == false)
            || (a.analystTicketRef?.isEmpty == false)
            || (a.analystNote?.isEmpty == false)
    }

    /// Map a raw analyst status ("new"/"investigating"/"resolved"/…) to a
    /// display label + chip color.
    private func analystStatusChip(_ status: String) -> (String, V2ChipKind) {
        switch status {
        case "resolved":       return ("Resolved", .healthy)
        case "false_positive": return ("False positive", .neutral)
        case "dismissed":      return ("Dismissed", .neutral)
        case "investigating":  return ("Investigating", .warning)
        case "new":            return ("New", .info)
        default:               return (status.capitalized, .info)
        }
    }

    /// History "Status" column: reflect the real analyst disposition rather
    /// than mislabeling every still-open alert as green "Resolved".
    private func historyStatusChip(_ a: V2MockAlert) -> (String, V2ChipKind) {
        if a.suppressed { return ("Suppressed", .neutral) }
        if let s = a.analystStatus, !s.isEmpty { return analystStatusChip(s) }
        return ("Open", .info)
    }

    private func liftSuppression(_ entry: V2SuppressionEntry) async {
        await submitMutations([.init(operation: .liftSuppression, targetID: entry.id,
                                     title: entry.ruleId, scope: entry.scope)])
    }

    private func suppressCampaign(_ campaign: V2MockCampaign) async {
        await submitMutations([.init(operation: .suppressCampaign, targetID: campaign.id,
                                     title: campaign.name)])
    }

    private func bulkSuppress(_ targets: [V2MockAlert]) async {
        let requests: [V2MutationRequest] = targets.filter { !$0.suppressed }.map {
            .init(operation: .suppressAlert, targetID: $0.id, title: $0.title)
        }
        await MainActor.run {
            selectedAlertIds.subtract(Set(requests.map(\.targetID)))
            lastUndoBatch = requests
        }
        await submitMutations(requests)
    }

    private func exportAlerts(_ targets: [V2MockAlert]) {
        let panel = NSSavePanel()
        panel.title = "Export alerts"
        // .data avoids macOS auto-rewriting the extension. With
        // .json set, the panel was forcing a .json suffix on top
        // of our .jsonl, producing "alerts-…json.jsonl".
        panel.allowedContentTypes = [.data]
        panel.allowsOtherFileTypes = true
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd-HHmm"
        formatter.timeZone = TimeZone.current
        let stamp = formatter.string(from: Date())
        panel.nameFieldStringValue = "maccrab-alerts-\(stamp).jsonl"
        panel.begin { response in
            guard response == .OK, let url = panel.url else { return }
            DispatchQueue.global(qos: .userInitiated).async {
                let lines: [String] = targets.compactMap { alert in
                    let record: [String: Any] = [
                        "id": alert.id,
                        "title": alert.title,
                        "severity": alert.severity.rawValue,
                        "rule_id": alert.ruleId,
                        "process": alert.process,
                        "process_path": alert.processPath,
                        "pid": alert.pid,
                        "category": alert.category,
                        "mitre": alert.mitre,
                        "description": alert.description,
                        // v1.11.1 (audit perf LOW): hoisted formatter
                        // (V2AlertsWorkspace exports a JSON dump on
                        // demand; pre-fix instantiated one per row).
                        "timestamp": V2AlertsWorkspace.isoFormatter.string(from: alert.timestamp),
                        "suppressed": alert.suppressed,
                    ]
                    guard let data = try? JSONSerialization.data(
                            withJSONObject: record,
                            options: [.sortedKeys]),
                          let s = String(data: data, encoding: .utf8) else { return nil }
                    return s
                }
                let payload = lines.joined(separator: "\n") + "\n"
                let writeOK = (try? payload.write(to: url, atomically: true, encoding: .utf8)) != nil
                DispatchQueue.main.async {
                    state.showToast(
                        writeOK
                          ? V2Toast(kind: .success,
                                    title: "Exported \(targets.count) alert\(targets.count == 1 ? "" : "s")",
                                    detail: url.lastPathComponent)
                          : V2Toast(kind: .error,
                                    title: "Export failed",
                                    detail: "Could not write \(url.path)")
                    )
                }
            }
        }
    }

    @ViewBuilder
    private var tabBody: some View {
        switch state.selectedTabs[.alerts] ?? .alertsOpen {
        case .alertsOpen:        openTab
        case .alertsCampaigns:   campaignsTab
        case .alertsHistory:     historyTab
        case .alertsSuppressions: suppressionsTab
        default: openTab
        }
    }

    // MARK: - Daemon-liveness gating (B6)

    /// A live provider with a fresh (<120 s) heartbeat — the only state
    /// in which an empty alerts table can be trusted as "all clear".
    /// The live provider's `mode` is hardcoded `.live` and never flips
    /// when the daemon dies, so we cross-check the heartbeat instead.
    private var daemonReporting: Bool {
        Self.isDaemonReporting(mode: state.provider.mode,
                               heartbeatStale: appState.heartbeat?.isStale,
                               heartbeatReady: appState.heartbeat?.isReady,
                               protectionDegraded: appState.isProtectionDegraded)
    }

    /// Pure decision seam for the B6 daemon-liveness gate. A live provider
    /// with a fresh (non-stale) heartbeat is the only state in which an
    /// empty Open / Campaigns / Suppressions list can be trusted as an
    /// "all clear" — offline/mock, a missing heartbeat, or a stale one all
    /// read as not-reporting, so the empty state is withheld and the stale
    /// banner shows instead. Extracted so the gate is unit-testable without
    /// standing up a SwiftUI view.
    static func isDaemonReporting(mode: V2DataSourceMode, heartbeatStale: Bool?,
                                  heartbeatReady: Bool?, protectionDegraded: Bool = false) -> Bool {
        mode == .live && heartbeatStale == false && heartbeatReady == true && !protectionDegraded
    }

    /// Warning banner for the Open/History tabs when we can't trust the
    /// numbers: a live/offline provider that isn't receiving fresh
    /// heartbeats is rendering a zero that may be a read failure, not an
    /// all-clear. Mock/dev sample data is exempt (it's knowingly
    /// synthetic). Renders nothing when the daemon is reporting.
    @ViewBuilder
    private var daemonStaleBanner: some View {
        if state.provider.mode != .mock && !daemonReporting {
            HStack(alignment: .top, spacing: 12) {
                ZStack {
                    Circle().fill(V2Theme.warning.opacity(0.18))
                    Image(systemName: "exclamationmark.triangle.fill")
                        .foregroundStyle(V2Theme.warning)
                        .scaledSystem(16, weight: .semibold)
                }
                .frame(width: 38, height: 38)
                VStack(alignment: .leading, spacing: 4) {
                    Text(String(localized: "alerts.daemonStaleTitle", defaultValue: "Protection is not confirmed — alert data may be incomplete"))
                        .scaledSystem(13, weight: .semibold)
                        .foregroundStyle(V2Theme.primaryText)
                    Text(String(localized: "alerts.daemonStaleDetail", defaultValue: "The engine is starting, not reporting, or needs attention. Review System health; an empty list does not confirm that no threats are present."))
                        .font(V2Theme.meta())
                        .foregroundStyle(V2Theme.mutedText)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Spacer()
            }
            .v2Panel()
        }
    }

    // MARK: - Open tab

    private var openTab: some View {
        // Compute `visible` (filtered + sorted) ONCE here and pass to
        // searchBarMemoized + alertsTableMemoized. Pre-memoization the
        // search bar called filteredAlerts(...) for the bulk-suppress count
        // and the table called it again for the rows — twice the
        // O(N log N) work per body re-eval, which fires on every
        // keystroke in the search field. severityCards previously
        // also called it 5× more (once per severity case); that's
        // now precomputed as a counts dict.
        let visible = filteredAlerts(severity: severityFilter.wrappedValue, applyExternalFilter: true)
        // B6: distinguish "genuinely no open alerts" (positive empty-
        // state) from "filter/search returned nothing but alerts exist"
        // (show the table). Based on the full un-suppressed population,
        // not the filtered `visible`.
        let hasOpenAlerts = alerts.contains { !$0.suppressed }
        // v1.12.9: inspector floats over the table's right edge
        // instead of pushing the table leftward. Pre-fix, an HStack
        // [table | inspector] forced the table + 340 pt inspector +
        // sidebar to sum to ~1424 pt of content; at the 1180 window
        // minimum the trailing edge overflowed the window and either
        // the inspector or the rightmost table columns became
        // unreachable depending on layout priority. ZStack keeps the
        // table at its natural width; the inspector covers the
        // rightmost ~340 pt with a slide-in transition and a left-
        // edge shadow so it reads as a floating sidebar (Mail-style
        // detail pane). The user can still see Severity / Alert /
        // Process — the columns that matter for triage — in the
        // un-covered ~620 pt on the left.
        return ZStack(alignment: .topTrailing) {
            VStack(alignment: .leading, spacing: 16) {
                daemonStaleBanner
                timeRangeChips
                if let window = state.pendingAlertsWindow {
                    histogramWindowBanner(window)
                }
                severityCards
                searchBarMemoized(visible: visible)
                if let readError = state.provider.alertsReadError {
                    // UX-02: a store read that threw returns [] exactly like a
                    // quiet machine, and the B6 heartbeat gate can't see it
                    // (heartbeat_rich.json is written independently of
                    // alerts.db). Pre-fix that rendered the green
                    // "you're clear" panel over a failed read. The flag
                    // self-clears on the next successful read, so a transient
                    // busy-DB failure resolves itself on the next tick.
                    V2ErrorState(
                        title: String(localized: "alerts.readFailedTitle", defaultValue: "Couldn't read alerts"),
                        body: String(localized: "alerts.readFailedBody", defaultValue: "The on-disk alert store could not be read (\(readError)), so this list is NOT an all-clear."),
                        retry: {
                            Task {
                                await state.reconnectLiveDataIfStale()
                                await reload()
                            }
                        }
                    )
                    .frame(minHeight: 280)
                    .v2Panel()
                } else if daemonReporting && loaded && !hasOpenAlerts {
                    V2EmptyState(
                        title: String(localized: "alerts.emptyOpenTitle", defaultValue: "No open alerts"),
                        body: String(localized: "alerts.emptyOpenBody", defaultValue: "No unsuppressed alerts appear in the selected time range. The engine is reporting active monitoring."),
                        icon: "checkmark.shield"
                    )
                    .frame(minHeight: 280)
                    .v2Panel()
                } else {
                    alertsTableMemoized(items: visible)
                }
            }
            .padding(16)
            .frame(maxWidth: .infinity, maxHeight: .infinity)

            if let alert = selected {
                alertInspector(for: alert)
                    .shadow(color: Color.black.opacity(0.25), radius: 8, x: -4, y: 0)
                    .transition(V2Motion.inspectorSlide(reduceMotion: reduceMotion))
            }
        }
        .animation(V2Motion.inspectorPresent(reduceMotion: reduceMotion), value: selected?.id)
    }

    /// Time-range chip group used by Open + History + Campaigns tabs.
    /// Chips drive `state.alertTimeRange` which the .task(id:) reload
    /// re-fetches on. Default 7d matches the campaigns empty-state
    /// copy promise.
    private var timeRangeChips: some View {
        HStack(spacing: 6) {
            ForEach(["24h", "7d", "30d", "all"], id: \.self) { key in
                let label: String = {
                    switch key {
                    case "24h": return "Last 24h"
                    case "7d":  return "Last 7d"
                    case "30d": return "Last 30d"
                    default:    return "All time"
                    }
                }()
                let on = state.alertTimeRange == key
                Button {
                    // D7: an explicit range chip overrides any active
                    // histogram window — clear it so the chip's range wins.
                    state.pendingAlertsWindow = nil
                    state.alertTimeRange = key
                } label: {
                    Text(label)
                        .font(V2Theme.meta())
                        .foregroundStyle(on ? V2Theme.primaryText : V2Theme.mutedText)
                        .padding(.horizontal, 10).padding(.vertical, 5)
                        .background(on ? V2Theme.panelBackground : .clear)
                        .overlay(
                            RoundedRectangle(cornerRadius: V2Theme.smallCornerRadius)
                                .stroke(V2Theme.panelBorder, lineWidth: on ? 1 : 0)
                        )
                        .clipShape(RoundedRectangle(cornerRadius: V2Theme.smallCornerRadius))
                        .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .accessibilityLabel("\(label) time range")
                .accessibilityAddTraits(on ? [.isSelected] : [])
            }
            Spacer()
        }
    }

    /// D7: banner surfaced when an Overview histogram bar tap narrowed the
    /// Open list to a single time bucket. Explains why the list is tighter
    /// than the highlighted range chip and offers a one-click clear — the
    /// same affordance the Events "Investigate" banner provides.
    private func histogramWindowBanner(_ window: V2TimeWindow) -> some View {
        let tf: DateFormatter = {
            let f = DateFormatter()
            f.dateStyle = .short
            f.timeStyle = .short
            return f
        }()
        return HStack(spacing: 8) {
            Image(systemName: "chart.bar.xaxis")
                .foregroundStyle(V2Theme.brand)
                .scaledSystem(12, weight: .semibold)
            Text(String(localized: "ui.V2AlertsWorkspace.filtered.to.the.tapped.window", defaultValue: "Filtered to the tapped window"))
                .font(V2Theme.meta())
                .foregroundStyle(V2Theme.primaryText)
            // WCAG 1.4.3: `brand` as body text is 3.90:1 light / 3.65:1 on a
            // panel. This is the time window the alert list is pinned to —
            // see V2Theme.brandText.
            Text("\(tf.string(from: window.start)) – \(tf.string(from: window.end))")
                .font(V2Theme.mono())
                .foregroundStyle(V2Theme.brandText)
                .lineLimit(1)
                .truncationMode(.middle)
            Spacer()
            Button { state.pendingAlertsWindow = nil } label: {
                HStack(spacing: 4) {
                    Image(systemName: "xmark")
                        .scaledSystem(9, weight: .semibold)
                    Text(String(localized: "ui.V2AlertsWorkspace.clear.window", defaultValue: "Clear window"))
                        .font(V2Theme.meta())
                }
                .foregroundStyle(V2Theme.mutedText)
                .padding(.horizontal, 8).padding(.vertical, 4)
                .background(V2Theme.panelBackground)
                .overlay(RoundedRectangle(cornerRadius: 4)
                            .stroke(V2Theme.panelBorder, lineWidth: 1))
                .clipShape(RoundedRectangle(cornerRadius: 4))
            }
            .buttonStyle(.plain)
            .accessibilityLabel(String(localized: "ui.V2AlertsWorkspace.clear.histogram.time.window", defaultValue: "Clear histogram time window"))
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
        .background(V2Theme.brand.opacity(0.08))
        .overlay(RoundedRectangle(cornerRadius: V2Theme.smallCornerRadius)
                    .stroke(V2Theme.brand.opacity(0.4), lineWidth: 1))
        .clipShape(RoundedRectangle(cornerRadius: V2Theme.smallCornerRadius))
    }

    private var severityCards: some View {
        // Pre-compute the per-severity counts ONCE here. Pre-fix this
        // called `filteredAlerts(severity: sev, applyExternalFilter: false)`
        // 5× per body re-eval (once per severity case via ForEach), and
        // `filteredAlerts` re-runs `filter + filter? + filter? + sorted`
        // over `self.alerts` (up to 200 rows) each call. Since the
        // search bar's Bulk-suppress count adds a 6th call, every
        // keystroke in the search field cost 1200-1600 row passes plus
        // 6 sorts. Now: one pass to bucket alerts (excluding the
        // search filter so the cards reflect the un-searched
        // population, matching pre-fix semantics) and the search box
        // result is computed separately exactly once.
        let nonSuppressed = self.alerts.filter { !$0.suppressed }
        var counts: [V2Severity: Int] = [:]
        for a in nonSuppressed { counts[a.severity, default: 0] += 1 }
        return HStack(spacing: 12) {
            ForEach(V2Severity.allCases, id: \.self) { sev in
                severityCard(severity: sev, count: counts[sev] ?? 0)
            }
        }
    }

    private func severityCard(severity: V2Severity, count: Int) -> some View {
        let isOn = severityFilter.wrappedValue == severity
        return Button {
            severityFilter.wrappedValue = isOn ? nil : severity
        } label: {
            VStack(alignment: .leading, spacing: 8) {
                HStack(spacing: 6) {
                    V2SeverityDot(severity.chipKind)
                    Text(severity.label.uppercased())
                        .font(V2Theme.cardTitle())
                        .foregroundStyle(V2Theme.mutedText)
                }
                Text("\(count)")
                    .scaledSystem(26, weight: .bold)
                    .foregroundStyle(V2Theme.primaryText)
                Text(count == 1 ? "1 alert" : "\(count) alerts")
                    .font(V2Theme.meta())
                    .foregroundStyle(V2Theme.mutedText)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(14)
            .background(severity.chipKind.color.opacity(isOn ? 0.18 : 0.06))
            .overlay(
                RoundedRectangle(cornerRadius: V2Theme.cornerRadius)
                    .stroke(severity.chipKind.color.opacity(isOn ? 0.5 : 0.2), lineWidth: 1)
            )
            .clipShape(RoundedRectangle(cornerRadius: V2Theme.cornerRadius))
        }
        .buttonStyle(.plain)
        .accessibilityLabel("\(severity.label), \(count) alerts. \(isOn ? "Filter active" : "Click to filter")")
    }

    /// Memoized variant: takes the already-computed `visible` list so
    /// it doesn't have to re-filter+re-sort on every keystroke.
    private func searchBarMemoized(visible: [V2MockAlert]) -> some View {
        HStack(spacing: 8) {
            HStack(spacing: 8) {
                Image(systemName: "magnifyingglass")
                    .foregroundStyle(V2Theme.mutedText)
                    .scaledSystem(12)
                TextField("Search alerts (rule, process, MITRE…)", text: query)
                    .textFieldStyle(.plain)
                    .font(V2Theme.body())
                    .foregroundStyle(V2Theme.primaryText)
                if !query.wrappedValue.isEmpty {
                    Button { query.wrappedValue = "" } label: {
                        Image(systemName: "xmark.circle.fill")
                            .foregroundStyle(V2Theme.tertiaryText)
                    }
                    .buttonStyle(.plain)
                    // WCAG 4.1.2: icon-only with no label and no tooltip.
                    .accessibilityLabel(String(localized: "ax.clearSearch", defaultValue: "Clear search"))
                }
            }
            .padding(.horizontal, 10)
            .padding(.vertical, 7)
            .background(V2Theme.panelBackground)
            .overlay(
                RoundedRectangle(cornerRadius: V2Theme.smallCornerRadius)
                    .stroke(V2Theme.panelBorder, lineWidth: 1)
            )
            .clipShape(RoundedRectangle(cornerRadius: V2Theme.smallCornerRadius))

            if severityFilter.wrappedValue != nil {
                V2ActionButton(String(localized: "ax.clearFilter", defaultValue: "Clear filter"), icon: "xmark", style: .ghost) {
                    severityFilter.wrappedValue = nil
                }
            }
            Spacer()
            let bulkTargets = bulkSuppressTargets(visible: visible)
            V2ActionButton(String(localized: "ui.V2AlertsWorkspace.bulk.suppress.8bd14f77", defaultValue: "Bulk suppress (\(bulkTargets.count))"),
                           icon: "bell.slash", style: .secondary,
                           disabled: bulkTargets.isEmpty,
                           tooltip: selectedAlertIds.isEmpty
                                ? "Suppress all \(visible.count) alerts currently visible in the table"
                                : "Suppress the \(bulkTargets.count) checked alert\(bulkTargets.count == 1 ? "" : "s")") {
                // Confirm before silencing a large batch; small batches run
                // straight through.
                if bulkTargets.count > bulkSuppressConfirmThreshold {
                    pendingBulkSuppress = bulkTargets
                } else {
                    Task { await bulkSuppress(bulkTargets) }
                }
            }
            V2ActionButton(String(localized: "ui.V2AlertsWorkspace.export", defaultValue: "Export (\(visible.count))"),
                           icon: "square.and.arrow.up", style: .secondary,
                           disabled: visible.isEmpty,
                           tooltip: "Export visible alerts as JSON Lines") {
                exportAlerts(visible)
            }
        }
    }

    /// Alerts table for the Open tab. Takes the already-computed `visible`
    /// rows so they aren't recomputed for the table on top of what
    /// `searchBarMemoized` already computed for its bulk-suppress badge.
    private func alertsTableMemoized(items: [V2MockAlert]) -> some View {
        // Multi-select: the checkbox column drives `selectedAlertIds` for
        // selective bulk-suppress; a row-body click still sets `selected` so
        // the inspector keeps opening as before.
        V2DataTable(
            columns: alertsTableColumns,
            items: items,
            selection: $selected,
            multiSelection: $selectedAlertIds
        )
    }

    /// Bulk-suppress target set: the checked subset when the operator has
    /// ticked specific rows, otherwise the full visible list (preserving the
    /// pre-multi-select "suppress everything visible" behaviour).
    private func bulkSuppressTargets(visible: [V2MockAlert]) -> [V2MockAlert] {
        guard !selectedAlertIds.isEmpty else { return visible }
        return visible.filter { selectedAlertIds.contains($0.id) }
    }

    /// Shared column definitions used by `alertsTableMemoized(items:)`.
    /// Building these inline per body re-eval allocated 6 V2DataColumn
    /// structs + their label closures on every keystroke.
    private var alertsTableColumns: [V2DataColumn<V2MockAlert>] {
        [
            V2DataColumn(id: "sev", title: "Severity", width: .fixed(96),
                         sortKey: { .number(Double($0.severity.sortOrder)) }) { a in
                V2StatusChip(a.severity.label, kind: a.severity.chipKind)
            },
            V2DataColumn(id: "title", title: "Alert", width: .flexible(min: 200),
                         sortKey: { .text($0.title) }) { a in
                VStack(alignment: .leading, spacing: 1) {
                    V2TableCellText(a.title, primary: true, lineLimit: 1)
                        // v1.21.5 (UI-test harness): per-row XCUITest id on the
                        // title cell — AlertsFlowUITest targets
                        // app.staticTexts["alert.row.<alert id>"].
                        .v2AXID("alert.row.\(a.id)")
                    V2TableCellText(a.ruleId, primary: false, mono: true, lineLimit: 1)
                }
            },
            V2DataColumn(id: "process", title: "Process", width: .flexible(min: 120, max: 220),
                         sortKey: { .text($0.process) }) { a in
                VStack(alignment: .leading, spacing: 1) {
                    V2TableCellText(a.process)
                    // v1.10.2 (audit functionality HIGH): pid is
                    // hardcoded to 0 by V2LiveDataProvider.toV2Alert
                    // because Alert doesn't persist process pid yet
                    // (schema-v2 migration is a v1.11 task). Render
                    // the sub-label only when a real pid exists,
                    // matching the inspector's `if pid > 0` gate.
                    if a.pid > 0 {
                        V2TableCellText("pid \(a.pid)", primary: false, mono: true)
                    }
                }
            },
            V2DataColumn(id: "category", title: "Category", width: .fixed(110),
                         sortKey: { .text($0.category) }) { a in
                V2TableCellText(a.category, primary: false)
            },
            V2DataColumn(id: "mitre", title: "MITRE", width: .fixed(120),
                         sortKey: { .text($0.mitre.first ?? "") }) { a in
                Text(a.mitre.first ?? "—")
                    .font(V2Theme.mono())
                    .foregroundStyle(V2Theme.mutedText)
            },
            V2DataColumn(id: "when", title: "When", width: .fixed(90),
                         sortKey: { .date($0.timestamp) }) { a in
                V2TableCellText(V2TimeFormat.relative(a.timestamp), primary: false)
            },
        ]
    }

    private func filteredAlerts(severity: V2Severity?, applyExternalFilter: Bool) -> [V2MockAlert] {
        var items = self.alerts.filter { !$0.suppressed }
        if let severity { items = items.filter { $0.severity == severity } }
        if applyExternalFilter {
            let q = query.wrappedValue.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            if !q.isEmpty {
                items = items.filter {
                    ($0.title.lowercased() + $0.ruleId + $0.process + $0.mitre.joined(separator: " "))
                        .lowercased().contains(q)
                }
            }
        }
        return items.sorted { ($0.severity.sortOrder, -$0.timestamp.timeIntervalSince1970)
                           <  ($1.severity.sortOrder, -$1.timestamp.timeIntervalSince1970) }
    }

    // MARK: - Inspector

    @ViewBuilder
    private func alertInspector(for alert: V2MockAlert) -> some View {
        V2Inspector(
            title: alert.title,
            subtitle: alert.ruleId,
            onClose: { selected = nil }
        ) {
            // Horizontal scroll so the severity chip + a long ATT&CK code list
            // stay reachable in the fixed-width inspector instead of clipping.
            ScrollView(.horizontal, showsIndicators: false) {
                HStack(spacing: 8) {
                    V2StatusChip(alert.severity.label, kind: alert.severity.chipKind)
                    ForEach(alert.mitre, id: \.self) { code in
                        // FIQ-7: humanize + link the bare ATT&CK code. Chip shows
                        // the normalized code, the full technique name is the
                        // tooltip, and clicking opens the canonical ATT&CK page.
                        if let urlString = ATTACKRef.url(forCode: code), let url = URL(string: urlString) {
                            Link(destination: url) {
                                V2StatusChip(ATTACKRef.normalize(code) ?? code, kind: .neutral, icon: "doc.plaintext")
                            }
                            .help(ATTACKRef.display(forCode: code))
                        } else {
                            V2StatusChip(code, kind: .neutral, icon: "doc.plaintext")
                        }
                    }
                }
            }
            // v1.18: parse the snapshotted triggering event(s) once; reused by
            // the "What happened" summary and the structured detail below.
            let triggers = parseTriggerEvents(from: alert.triggeringEventsJson)
            if let summary = contextualSummary(for: alert, events: triggers) {
                V2InspectorSection(String(localized: "inspector.whatHappened", defaultValue: "What happened")) {
                    Text(summary)
                        .font(V2Theme.body())
                        .foregroundStyle(V2Theme.primaryText)
                        .textSelection(.enabled)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            V2InspectorSection(String(localized: "inspector.detectionRule", defaultValue: "Detection rule")) {
                Text(alert.description)
                    .font(V2Theme.body())
                    .foregroundStyle(V2Theme.primaryText)
                    .fixedSize(horizontal: false, vertical: true)
            }
            V2InspectorSection(String(localized: "inspector.process", defaultValue: "Process")) {
                V2InspectorKeyValue("Name",   alert.process)
                if !alert.processPath.isEmpty {
                    V2InspectorKeyValue("Path",   alert.processPath, mono: true)
                }
                if alert.pid > 0 {
                    V2InspectorKeyValue("PID",    "\(alert.pid)", mono: true)
                }
                if !alert.parent.isEmpty {
                    V2InspectorKeyValue("Parent", alert.parent, mono: true)
                }
                if !alert.user.isEmpty {
                    V2InspectorKeyValue("User",   alert.user)
                }
                // v1.12.6 Wave 9H: Wave-2 alerts.db schema additions —
                // ai_tool, working_directory, process_sha256, host_name.
                // Hide each row when its column is empty (pre-9H alerts
                // have NULL in these columns and render identically).
                if !alert.workingDirectory.isEmpty {
                    V2InspectorKeyValue("CWD",    alert.workingDirectory, mono: true)
                }
                if !alert.aiTool.isEmpty {
                    V2InspectorKeyValue("AI tool", alert.aiTool)
                }
                if !alert.processSHA256.isEmpty {
                    V2InspectorKeyValue("SHA-256", alert.processSHA256, mono: true)
                }
                if !alert.hostName.isEmpty {
                    V2InspectorKeyValue("Host",   alert.hostName, mono: true)
                }
            }
            V2InspectorSection(String(localized: "inspector.when", defaultValue: "When")) {
                V2InspectorKeyValue("Detected", V2TimeFormat.absolute(alert.timestamp), mono: true)
                V2InspectorKeyValue("Relative", V2TimeFormat.relative(alert.timestamp))
            }
            if !alert.actionsTaken.isEmpty {
                V2InspectorSection(String(localized: "inspector.actionsTaken", defaultValue: "Actions taken")) {
                    ForEach(alert.actionsTaken, id: \.self) { act in
                        HStack(spacing: 6) {
                            Image(systemName: "checkmark.circle.fill")
                                .foregroundStyle(V2Theme.healthy)
                                .scaledSystem(11)
                            Text(act).font(V2Theme.body()).foregroundStyle(V2Theme.primaryText)
                        }
                    }
                }
            }
            // Deterministic, LLM-free "What To Do": AlertStore persists
            // remediation_hint + d3fend_techniques (schema v3) and
            // AlertSink fills them from the alert's ATT&CK tactics, so
            // even a no-LLM operator gets actionable guidance. The
            // D3FEND chips link out to the technique reference.
            if let hint = alert.remediationHint, !hint.isEmpty {
                V2InspectorSection(String(localized: "inspector.whatToDo", defaultValue: "What to do")) {
                    Text(hint)
                        .font(V2Theme.body())
                        .foregroundStyle(V2Theme.primaryText)
                        .fixedSize(horizontal: false, vertical: true)
                        .textSelection(.enabled)
                }
            } else {
                // Legacy alerts (and rules with no ATT&CK/D3FEND mapping) carry
                // no persisted remediation_hint, so the section was simply
                // absent — the operator got zero guidance. Fall back to a
                // deterministic, LLM-free triage checklist so "What to do" is
                // never empty.
                V2InspectorSection(String(localized: "inspector.whatToDo", defaultValue: "What to do")) {
                    Text(defaultRemediation(for: alert))
                        .font(V2Theme.body())
                        .foregroundStyle(V2Theme.primaryText)
                        .fixedSize(horizontal: false, vertical: true)
                        .textSelection(.enabled)
                }
            }
            if !alert.d3fendTechniques.isEmpty {
                V2InspectorSection(String(localized: "inspector.d3fend", defaultValue: "D3FEND defenses")) {
                    FlowingChips(items: alert.d3fendTechniques, kind: .info) { tech in
                        // Use the shared, verified id→technique URL (the raw
                        // dotted code 404s; D3FENDMapping holds the canonical
                        // slug). Unknown ids fall back to the D3FEND matrix.
                        let urlString = D3FENDMapping.ref(forID: tech)?.url ?? "https://d3fend.mitre.org/"
                        if let url = URL(string: urlString) {
                            NSWorkspace.shared.open(url)
                        }
                    }
                }
            }
            if let summary = alert.llmSummary, !summary.isEmpty {
                V2InspectorSection(String(localized: "inspector.aiAnalysis", defaultValue: "AI analysis")) {
                    VStack(alignment: .leading, spacing: 6) {
                        HStack(spacing: 6) {
                            if let v = alert.llmVerdict {
                                V2StatusChip(v.replacingOccurrences(of: "_", with: " "),
                                             kind: verdictChipKind(v))
                            }
                            if let c = alert.llmConfidence {
                                Text(String(localized: "ui.final.confidence", defaultValue: "Confidence: \(Int(c * 100))%"))
                                    .font(V2Theme.meta())
                                    .foregroundStyle(V2Theme.mutedText)
                            }
                            Spacer()
                            if let m = alert.llmModel {
                                Text(m)
                                    .font(V2Theme.meta())
                                    .foregroundStyle(V2Theme.tertiaryText)
                            }
                        }
                        Text(summary)
                            .font(V2Theme.body())
                            .foregroundStyle(V2Theme.primaryText)
                            .fixedSize(horizontal: false, vertical: true)
                            .textSelection(.enabled)
                        if !alert.llmSuggestedActions.isEmpty {
                            Text(String(localized: "ui.V2AlertsWorkspace.suggested.actions", defaultValue: "Suggested actions:"))
                                .font(V2Theme.meta())
                                .foregroundStyle(V2Theme.mutedText)
                                .padding(.top, 4)
                            ForEach(alert.llmSuggestedActions, id: \.self) { a in
                                HStack(alignment: .top, spacing: 6) {
                                    // v1.11.0 (audit UX MEDIUM): use .forward
                                    // variant so the arrow mirrors under
                                    // RTL locales.
                                    Image(systemName: "arrow.forward.circle.fill")
                                        .foregroundStyle(V2Theme.aiAccent)
                                        .scaledSystem(11)
                                        .padding(.top, 2)
                                    Text(a)
                                        .font(V2Theme.body())
                                        .foregroundStyle(V2Theme.primaryText)
                                }
                            }
                        }
                    }
                }
            }
            // Analyst workflow metadata (status / owner / ticket / notes) is
            // plumbed all the way DB → provider → model but was never rendered.
            // Show it read-only when present. (Inline mutation to SET status /
            // owner would need a provider write method — tracked separately.)
            if hasAnalystMetadata(alert) {
                V2InspectorSection(String(localized: "inspector.analyst", defaultValue: "Analyst")) {
                    if let status = alert.analystStatus, !status.isEmpty {
                        HStack(spacing: 6) {
                            Text(String(localized: "inspector.analystStatus", defaultValue: "Status"))
                                .font(V2Theme.meta())
                                .foregroundStyle(V2Theme.mutedText)
                            let chip = analystStatusChip(status)
                            V2StatusChip(chip.0, kind: chip.1)
                        }
                    }
                    if let owner = alert.analystOwner, !owner.isEmpty {
                        V2InspectorKeyValue("Owner", owner)
                    }
                    if let ticket = alert.analystTicketRef, !ticket.isEmpty {
                        V2InspectorKeyValue("Ticket", ticket, mono: true)
                    }
                    if let note = alert.analystNote, !note.isEmpty {
                        Text(note)
                            .font(V2Theme.body())
                            .foregroundStyle(V2Theme.primaryText)
                            .fixedSize(horizontal: false, vertical: true)
                            .textSelection(.enabled)
                    }
                }
            }
            // v1.17.2 / v1.18: the EXACT triggering event(s), snapshotted onto
            // the alert at creation (AlertStore schema v6) and rendered as
            // structured fields. Unlike "Surrounding events", this survives
            // events.db pruning — so even a months-old alert still shows what
            // actually fired. `triggers` is parsed once at the top of the
            // inspector.
            if !triggers.isEmpty {
                V2InspectorSection(String(localized: "inspector.triggeringEvent", defaultValue: "Triggering event")) {
                    VStack(alignment: .leading, spacing: 10) {
                        ForEach(Array(triggers.enumerated()), id: \.offset) { _, ev in
                            triggerEventCard(ev)
                        }
                        Text(String(localized: "ui.V2AlertsWorkspace.captured.at.alert.time.preserved.even.after", defaultValue: "Captured at alert time — preserved even after the live event is pruned."))
                            .font(V2Theme.meta())
                            .foregroundStyle(V2Theme.mutedText)
                    }
                }
            }
            V2InspectorSection(String(localized: "inspector.surroundingEvents2Min", defaultValue: "Surrounding events (±2 min)")) {
                SurroundingEventsView(alert: alert, appState: appState)
            }
            V2InspectorSection(String(localized: "inspector.traceContext", defaultValue: "Trace context")) {
                VStack(alignment: .leading, spacing: 6) {
                    Text(String(localized: "ui.V2AlertsWorkspace.inspect.this.alert.s.full.causal.trace", defaultValue: "Inspect this alert's full causal trace via the CLI:"))
                        .font(V2Theme.meta())
                        .foregroundStyle(V2Theme.mutedText)
                    HStack(spacing: 6) {
                        Text(verbatim: "maccrabctl trace from-alert \(alert.id)")
                            .font(V2Theme.mono())
                            .foregroundStyle(V2Theme.primaryText)
                            .textSelection(.enabled)
                            .lineLimit(1)
                            .truncationMode(.middle)
                        Spacer()
                        V2ActionButton(String(localized: "ui.V2AlertsWorkspace.copy", defaultValue: "Copy"), icon: "doc.on.doc", style: .ghost) {
                            NSPasteboard.general.clearContents()
                            NSPasteboard.general.setString("maccrabctl trace from-alert \(alert.id)", forType: .string)
                            state.showToast(V2Toast(kind: .success, title: "Command copied", detail: nil))
                        }
                    }
                }
            }
            V2InspectorSection(String(localized: "inspector.actions", defaultValue: "Actions")) {
                // v1.18.1: compact action bar — the primary verb gets the
                // full row; the two secondary verbs share one row at equal
                // width (the old layout stacked all three full-width).
                VStack(alignment: .leading, spacing: 8) {
                    V2ActionButton(String(localized: "ui.V2AlertsWorkspace.investigate.in.events", defaultValue: "Investigate in Events"), icon: "magnifyingglass", style: .primary, fullWidth: true) {
                        let filter = !alert.processPath.isEmpty
                            ? alert.processPath
                            : (alert.process != "—" ? alert.process : alert.ruleId)
                        state.pendingEventsFilter = filter
                        // Centre the events query on the alert's
                        // firing time. Half-window 30 min covers
                        // typical "events around the time this rule
                        // fired" without drowning the user in the
                        // firehose. Pre-fix the events list defaulted
                        // to "Last 24 hours" regardless of when the
                        // alert was — even alerts from 60+ days ago
                        // surfaced today's matching events.
                        state.pendingEventsCenterTime = alert.timestamp
                        state.pendingEventsHalfWindowSeconds = 30 * 60
                        state.switchWorkspace(.events)
                    }
                    .frame(maxWidth: .infinity)
                    HStack(spacing: 8) {
                        if alert.ruleId.hasPrefix("maccrab.campaign.") {
                            // A campaign alert is a correlation across many
                            // alerts, not an editable Sigma rule — "Open rule"
                            // would dead-end on the built-in explanation note.
                            // Route to the Campaigns tab, where the correlation
                            // actually lives. (The alert carries no campaign id,
                            // so we open the list rather than a specific one.)
                            V2ActionButton(String(localized: "workspaceTab.alerts.campaigns", defaultValue: "Campaigns"), icon: "square.stack.3d.up", style: .secondary, fullWidth: true,
                                           tooltip: "This alert is a campaign correlation — open the Campaigns tab") {
                                state.goto(V2NavigationDestination(
                                    workspace: .alerts,
                                    tab: .alertsCampaigns
                                ))
                            }
                            .frame(maxWidth: .infinity)
                        } else {
                            V2ActionButton(String(localized: "ui.V2AlertsWorkspace.open.rule", defaultValue: "Open rule"), icon: "shield.lefthalf.filled", style: .secondary, fullWidth: true,
                                           tooltip: "Jump to this rule in Detection › Rules") {
                                // Pre-fill the rule search query so the rules
                                // table filters down to this rule, plus carry
                                // the rule id as the entity selection so the
                                // inspector opens automatically.
                                state.ruleSearchQuery = alert.ruleId
                                state.goto(V2NavigationDestination(
                                    workspace: .detection,
                                    tab: .detectionRules,
                                    entityId: alert.ruleId
                                ))
                            }
                            .frame(maxWidth: .infinity)
                        }
                        V2ActionButton(String(localized: "components.suppress", defaultValue: "Suppress"), icon: "bell.slash", style: .secondary, fullWidth: true,
                                       disabled: alert.suppressed,
                                       tooltip: alert.suppressed
                                            ? "Already suppressed"
                                            : "Mark this alert as suppressed in the alert store",
                                       // v1.21.5 (UI-test harness): AlertsFlowUITest
                                       // clicks app.buttons["alert.suppress.<alert id>"].
                                       axId: "alert.suppress.\(alert.id)") {
                            Task { await suppress(alert) }
                        }
                        .frame(maxWidth: .infinity)
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
    }

    /// List up to 8 events from AppState.events whose timestamp is
    /// within ±2 minutes of the alert. AppState already polls a
    /// A structured view of one snapshotted triggering event, parsed from the
    /// v6 JSON. Only the fields that drive the inspector — kept small.
    fileprivate struct TriggerEvent {
        var action: String
        var processName: String
        var processPath: String?
        var commandLine: String?
        var filePath: String?
        var fileAction: String?
        var destination: String?
        var signer: String?
        var notarized: Bool?
        var sha256: String?
        var parent: String?
        var user: String?
    }

    /// Parse the v6 triggering-event snapshot (a JSON array of event raw_json
    /// objects) into structured events. Pure value transform — no DB round
    /// trip. Tolerant of malformed/partial JSON (returns [] so the section
    /// simply hides).
    private func parseTriggerEvents(from json: String) -> [TriggerEvent] {
        guard !json.isEmpty, let data = json.data(using: .utf8),
              let arr = (try? JSONSerialization.jsonObject(with: data)) as? [[String: Any]]
        else { return [] }
        func nonEmpty(_ v: Any?) -> String? {
            guard let s = v as? String, !s.isEmpty else { return nil }
            return s
        }
        return arr.compactMap { obj -> TriggerEvent? in
            // Omitted-oversize marker (see EventSnapshot.encode).
            if let snap = obj["snapshot"] as? String, snap == "omitted" { return nil }
            let proc = obj["process"] as? [String: Any]
            let sig = proc?["codeSignature"] as? [String: Any]
            var signer: String? = nil
            if let st = nonEmpty(sig?["signerType"]) {
                let team = nonEmpty(sig?["teamId"]).map { " (\($0))" } ?? ""
                signer = st + team
            }
            var dest: String? = nil
            if let net = obj["network"] as? [String: Any] {
                let base = nonEmpty(net["destinationHostname"]) ?? nonEmpty(net["destinationIp"])
                if let base {
                    let port = (net["destinationPort"] as? Int).map { ":\($0)" } ?? ""
                    dest = base + port
                }
            }
            let ancestors = proc?["ancestors"] as? [[String: Any]]
            return TriggerEvent(
                action: nonEmpty(obj["eventAction"]) ?? nonEmpty(obj["eventType"]) ?? "event",
                processName: nonEmpty(proc?["name"]) ?? "—",
                processPath: nonEmpty(proc?["executable"]),
                commandLine: nonEmpty(proc?["commandLine"]),
                filePath: nonEmpty((obj["file"] as? [String: Any])?["path"]),
                fileAction: nonEmpty((obj["file"] as? [String: Any])?["action"]),
                destination: dest,
                signer: signer,
                notarized: sig?["isNotarized"] as? Bool,
                sha256: nonEmpty((proc?["hashes"] as? [String: Any])?["sha256"]),
                parent: nonEmpty(ancestors?.first?["executable"]),
                user: nonEmpty(proc?["userName"])
            )
        }
    }

    /// Build a factual one-line "what happened" sentence from the first
    /// triggering event. Tasteful — echoes the real event, no embellishment.
    private func contextualSummary(for alert: V2MockAlert, events: [TriggerEvent]) -> String? {
        guard let e = events.first else { return nil }
        var who = e.processName
        if let p = e.parent {
            who += " (via \((p as NSString).lastPathComponent))"
        }
        let did: String
        if let cmd = e.commandLine, cmd != e.processPath {
            did = "ran  \(cmd)"
        } else if let f = e.filePath {
            did = "\(e.fileAction ?? "accessed")  \(f)"
        } else if let d = e.destination {
            did = "connected to  \(d)"
        } else {
            did = e.action
        }
        return "\(who)  \(did)"
    }

    @ViewBuilder
    private func triggerEventCard(_ ev: TriggerEvent) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            V2InspectorKeyValue("Action", ev.action)
            if let p = ev.processPath { V2InspectorKeyValue("Process", p, mono: true) }
            if let c = ev.commandLine { V2InspectorKeyValue("Command", c, mono: true) }
            if let f = ev.filePath {
                V2InspectorKeyValue(ev.fileAction.map { $0.capitalized } ?? "File", f, mono: true)
            }
            if let d = ev.destination { V2InspectorKeyValue("Destination", d, mono: true) }
            if let s = ev.signer { V2InspectorKeyValue("Signer", s) }
            if let n = ev.notarized { V2InspectorKeyValue("Notarized", n ? "yes" : "no") }
            if let h = ev.sha256 { V2InspectorKeyValue("SHA-256", h, mono: true) }
            if let p = ev.parent { V2InspectorKeyValue("Parent", p, mono: true) }
            if let u = ev.user { V2InspectorKeyValue("User", u) }
        }
    }

    /// Renders the events surrounding an alert. Prefers the in-memory recent
    /// window (free, no DB round-trip); when that is empty — the common case
    /// once an alert is older than the events.db hot tier — it falls back to the
    /// `alert_evidence` snapshot the daemon captured at fire time, which survives
    /// pruning. Pre-fix this only read the in-memory cache, so "show events" on
    /// an aged-out alert was always blank.
    private struct SurroundingEventsView: View {
        let alert: V2MockAlert
        @ObservedObject var appState: AppState
        @State private var evidence: [Event] = []
        @State private var loaded = false

        var body: some View {
            let window: TimeInterval = 120
            let lo = alert.timestamp.addingTimeInterval(-window)
            let hi = alert.timestamp.addingTimeInterval(+window)
            let nearby = appState.events
                .filter { $0.timestamp >= lo && $0.timestamp <= hi }
                .sorted { $0.timestamp < $1.timestamp }
                .prefix(8)
            VStack(alignment: .leading, spacing: 4) {
                if !nearby.isEmpty {
                    ForEach(Array(nearby), id: \.id) { ev in
                        row(time: ev.timestamp, name: ev.processName, cat: ev.category.rawValue)
                    }
                } else if !evidence.isEmpty {
                    Text(String(localized: "ui.V2AlertsWorkspace.from.the.snapshot.captured.when.the.alert", defaultValue: "From the snapshot captured when the alert fired — the live events have since been pruned:"))
                        .font(V2Theme.meta())
                        .foregroundStyle(V2Theme.mutedText)
                    ForEach(Array(evidence.prefix(8)), id: \.id) { ev in
                        row(time: ev.timestamp, name: ev.process.name, cat: ev.eventCategory.rawValue)
                    }
                } else if loaded {
                    Text(String(localized: "ui.V2AlertsWorkspace.no.surrounding.events.were.captured.for.this", defaultValue: "No surrounding events were captured for this alert."))
                        .font(V2Theme.meta())
                        .foregroundStyle(V2Theme.mutedText)
                } else {
                    Text(String(localized: "ui.V2AlertsWorkspace.loading.captured.events", defaultValue: "Loading captured events…"))
                        .font(V2Theme.meta())
                        .foregroundStyle(V2Theme.mutedText)
                }
            }
            .task(id: alert.id) {
                loaded = false
                evidence = []
                // Only hit the DB when the free in-memory window has nothing.
                if nearby.isEmpty {
                    evidence = await appState.fetchEvidence(alertId: alert.id)
                }
                loaded = true
            }
        }

        @ViewBuilder
        private func row(time: Date, name: String, cat: String) -> some View {
            HStack(alignment: .top, spacing: 6) {
                Text(V2TimeFormat.short(time))
                    .font(V2Theme.mono())
                    .foregroundStyle(V2Theme.tertiaryText)
                    .frame(width: 70, alignment: .leading)
                Text(name)
                    .font(V2Theme.body())
                    .foregroundStyle(V2Theme.primaryText)
                    .lineLimit(1)
                Spacer()
                Text(cat)
                    .font(V2Theme.meta())
                    .foregroundStyle(V2Theme.mutedText)
            }
        }
    }

    // MARK: - Other tabs

    private var campaignsTab: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                // B6: without this an empty campaigns list on a dead/stale daemon
                // rendered a reassuring "No active campaigns" all-clear — the
                // same "daemon-down looks safe" trap the Open/History tabs guard
                // against. Show the stale banner and only show the all-clear
                // empty state when the engine is actually reporting.
                daemonStaleBanner
                timeRangeChips
                if !campaigns.isEmpty {
                    campaignsToolbar
                }
                if !campaigns.isEmpty {
                    ForEach(campaigns) { campaign in
                        campaignCard(campaign)
                    }
                } else if daemonReporting && loaded {
                    V2EmptyState(
                        title: "No active campaigns",
                        body: "MacCrab has not detected any multi-step attack campaigns in the selected time range.",
                        icon: "flame"
                    )
                    .frame(minHeight: 280)
                    .v2Panel()
                }
                if !suppressedCampaigns.isEmpty {
                    suppressedCampaignsSection
                }
            }
            .padding(16)
        }
    }

    /// In-UI restore surface (replaces the old "use the CLI" dead-end). Lists
    /// campaigns currently suppressed, each with a Restore button that calls
    /// provider.unsuppressCampaign + brings it back into the active list.
    private var suppressedCampaignsSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(String(localized: "ui.V2AlertsWorkspace.suppressed.campaigns", defaultValue: "Suppressed campaigns (\(suppressedCampaigns.count))"))
                .scaledSystem(12, weight: .semibold)
                .foregroundStyle(V2Theme.tertiaryText)
                .textCase(.uppercase)
                .padding(.top, 8)
            ForEach(suppressedCampaigns) { c in
                HStack(spacing: 12) {
                    Image(systemName: "flame")
                        .foregroundStyle(c.severity.chipKind.color)
                        .scaledSystem(14)
                    VStack(alignment: .leading, spacing: 1) {
                        Text(c.name).scaledSystem(13, weight: .medium)
                        Text(String(localized: "ui.final.suppressedAlerts", defaultValue: "Alerts: \(c.alertCount) · suppressed"))
                            .scaledSystem(11).foregroundStyle(V2Theme.mutedText)
                    }
                    Spacer()
                    V2ActionButton(String(localized: "ui.V2AlertsWorkspace.restore", defaultValue: "Restore"), icon: "bell", style: .secondary,
                                   tooltip: "Unsuppress this campaign and its contributing alerts.") {
                        Task { await restoreCampaign(c) }
                    }
                }
                .padding(10)
                .v2Panel()
            }
        }
    }

    private func restoreCampaign(_ campaign: V2MockCampaign) async {
        await submitMutations([.init(operation: .unsuppressCampaign, targetID: campaign.id,
                                     title: campaign.name)])
    }

    private func campaignCard(_ c: V2MockCampaign) -> some View {
        let isSelected = selectedCampaignIds.contains(c.id)
        return VStack(alignment: .leading, spacing: 12) {
            HStack(alignment: .top, spacing: 12) {
                Button {
                    if isSelected {
                        selectedCampaignIds.remove(c.id)
                    } else {
                        selectedCampaignIds.insert(c.id)
                    }
                } label: {
                    Image(systemName: isSelected ? "checkmark.square.fill" : "square")
                        .foregroundStyle(isSelected ? V2Theme.brand : V2Theme.mutedText)
                        .scaledSystem(16)
                }
                .buttonStyle(.plain)
                .help(isSelected ? "Deselect this campaign" : "Select for bulk-suppress")
                ZStack {
                    RoundedRectangle(cornerRadius: 8)
                        .fill(c.severity.chipKind.color.opacity(0.18))
                    Image(systemName: "flame.fill")
                        .foregroundStyle(c.severity.chipKind.color)
                        .scaledSystem(18, weight: .bold)
                }
                .frame(width: 40, height: 40)
                VStack(alignment: .leading, spacing: 2) {
                    Text(c.name)
                        .scaledSystem(15, weight: .semibold)
                        .foregroundStyle(V2Theme.primaryText)
                    // v1.12.6 Wave 9J: revive entity count now that
                    // toV2Campaign populates `entities` from the
                    // Wave-2 affectedUsers + affectedExecutables
                    // arrays (pre-9J it was hardcoded 0, and the v1.11
                    // audit had hidden the suffix as a result). Also
                    // appends process-tree depth + AI-tool count when
                    // non-zero so the operator can size the blast
                    // radius from the card without opening the
                    // inspector.
                    var metaSuffix: String {
                        var parts: [String] = ["\(c.alertCount) alerts",
                                                V2TimeFormat.relative(c.firstSeen)]
                        if c.entities > 0 { parts.append("\(c.entities) entities") }
                        if c.processTreeDepth > 0 {
                            parts.append("depth \(c.processTreeDepth)")
                        }
                        if !c.aiTools.isEmpty {
                            parts.append("\(c.aiTools.count) AI tool\(c.aiTools.count == 1 ? "" : "s")")
                        }
                        return parts.joined(separator: " · ")
                    }
                    Text(metaSuffix)
                        .font(V2Theme.meta())
                        .foregroundStyle(V2Theme.mutedText)
                }
                Spacer()
                V2StatusChip(c.severity.label, kind: c.severity.chipKind)
                V2ActionButton(String(localized: "sidebar.group.investigate", defaultValue: "Investigate"), icon: "magnifyingglass", style: .secondary) {
                    // Filter the Alerts Open list to the alerts that
                    // built this campaign. Pre-fix this set the query to
                    // `c.name`, but the alert search only matches
                    // title/ruleId/process/mitre — a campaign name
                    // matches none of them, so the table always came up
                    // empty. The campaign carries no contributing-alert
                    // ids, so we search on the strongest join key it
                    // *does* expose: a shared ATT&CK technique (its
                    // `techniques` are the union of its alerts' MITRE
                    // codes, so this matches the MITRE column), falling
                    // back to a contributing executable's binary name
                    // (matches the Process column). With neither, clear
                    // the search so the full Open list shows rather than
                    // an empty one.
                    let joinKey = c.techniques.first
                        ?? c.affectedExecutables.first.map { ($0 as NSString).lastPathComponent }
                    state.alertSearchQuery = joinKey ?? ""
                    state.alertSeverityFilter = nil
                    state.goto(V2NavigationDestination(
                        workspace: .alerts, tab: .alertsOpen
                    ))
                }
                V2ActionButton(String(localized: "components.suppress", defaultValue: "Suppress"), icon: "bell.slash", style: .secondary,
                               tooltip: "Suppress this campaign and every contributing alert. Restore it any time from the Suppressed campaigns section below.") {
                    Task { await suppressCampaign(c) }
                }
            }
            Text(c.summary)
                .font(V2Theme.body())
                .foregroundStyle(V2Theme.neutral)
                .fixedSize(horizontal: false, vertical: true)
            HStack(spacing: 6) {
                Text(String(localized: "ui.V2AlertsWorkspace.tactics", defaultValue: "Tactics:")).font(V2Theme.cardTitle()).foregroundStyle(V2Theme.tertiaryText)
                ForEach(c.tactics, id: \.self) { t in
                    V2StatusChip(t, kind: .neutral)
                }
            }
            HStack(spacing: 0) {
                ForEach(c.killChainStages.indices, id: \.self) { i in
                    let stage = c.killChainStages[i]
                    Text(stage)
                        .font(V2Theme.meta())
                        .foregroundStyle(V2Theme.mutedText)
                        .padding(.horizontal, 8)
                        .padding(.vertical, 4)
                        .background(V2Theme.panelBackground)
                        .clipShape(RoundedRectangle(cornerRadius: 4))
                    if i < c.killChainStages.count - 1 {
                        Image(systemName: "arrow.forward")
                            .scaledSystem(9)
                            .foregroundStyle(V2Theme.tertiaryText)
                            .padding(.horizontal, 4)
                    }
                }
            }
            // v1.12.6 Wave 9J: Wave-2 schema additions surfaced as
            // collapsed rows under the kill chain. Each row hidden
            // when its underlying array is empty so pre-Wave-2
            // campaigns render identically (data was always NULL).
            if !c.affectedUsers.isEmpty {
                campaignChipRow(label: "Users", values: c.affectedUsers)
            }
            if !c.affectedExecutables.isEmpty {
                campaignChipRow(label: "Executables", values: c.affectedExecutables, mono: true)
            }
            if !c.aiTools.isEmpty {
                campaignChipRow(label: "AI tools", values: c.aiTools)
            }
            if !c.techniques.isEmpty {
                campaignChipRow(label: "Techniques", values: c.techniques, mono: true)
            }
        }
        .v2Panel()
    }

    /// v1.12.6 Wave 9J: shared chip-row layout for the new campaign
    /// fields. Caps display at 8 chips so a wide affected-executables
    /// set doesn't blow the card layout — surfaces the rest as a
    /// trailing "+N more" chip. Uses a horizontal ScrollView so the
    /// row stays single-line even when chips overflow the card.
    @ViewBuilder
    private func campaignChipRow(label: String, values: [String], mono: Bool = false) -> some View {
        HStack(alignment: .top, spacing: 6) {
            Text("\(label):")
                .font(V2Theme.cardTitle())
                .foregroundStyle(V2Theme.tertiaryText)
                .frame(width: 88, alignment: .leading)
            let cap = 8
            let head = Array(values.prefix(cap))
            ScrollView(.horizontal, showsIndicators: false) {
                HStack(spacing: 4) {
                    ForEach(head, id: \.self) { v in
                        Text(v)
                            .font(mono ? V2Theme.mono() : V2Theme.meta())
                            .foregroundStyle(V2Theme.mutedText)
                            .padding(.horizontal, 6)
                            .padding(.vertical, 2)
                            .background(V2Theme.panelBackground)
                            .clipShape(RoundedRectangle(cornerRadius: 4))
                            .lineLimit(1)
                    }
                    if values.count > cap {
                        Text(String(localized: "ui.finalPrefix.V2AlertsWorkspace.more", defaultValue: "+\(values.count - cap) more"))
                            .font(V2Theme.meta())
                            .foregroundStyle(V2Theme.tertiaryText)
                    }
                }
            }
        }
    }

    private var historyTab: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                daemonStaleBanner
                timeRangeChips
                // An Overview histogram bar tap narrows `self.alerts` to a
                // single [start, end] window in reload(); that same window
                // applies to the History tab. Surface the same banner + clear
                // affordance the Open tab shows, so a silently-narrowed History
                // list is explained and dismissable.
                if let window = state.pendingAlertsWindow {
                    histogramWindowBanner(window)
                }
                Text(String(localized: "ui.V2AlertsWorkspace.resolved.suppressed.alerts.from.the.recent.retention", defaultValue: "Resolved + suppressed alerts from the recent retention window. Right-click a row for Unsuppress and Delete actions, or use the inspector buttons."))
                    .font(V2Theme.body())
                    .foregroundStyle(V2Theme.mutedText)
                // v1.18.1: dedupe — a suppressed alert inside the last 4
                // used to appear in both halves, giving the ForEach
                // duplicate ids (undefined Table diffing + console warnings).
                let suppressed = self.alerts.filter { $0.suppressed }
                // v1.21.4: the "Resolved" rows are the 4 *most recent*
                // non-suppressed alerts. Pre-fix used `self.alerts.suffix(4)`
                // on an unsorted array, so the rows were whatever happened
                // to sit at the array tail — not the newest alerts. Filtering
                // to non-suppressed also makes them disjoint from `suppressed`
                // by construction (so the old id-dedup is no longer needed).
                let resolved = self.alerts
                    .filter { !$0.suppressed }
                    .sorted { $0.timestamp > $1.timestamp }
                    .prefix(4)
                let history = suppressed + resolved
                V2DataTable(
                    columns: [
                        V2DataColumn(id: "sev", title: "Severity", width: .fixed(96),
                                     sortKey: { .number(Double($0.severity.sortOrder)) }) { a in
                            V2StatusChip(a.severity.label, kind: a.severity.chipKind)
                        },
                        V2DataColumn(id: "title", title: "Alert", width: .flexible(min: 240),
                                     sortKey: { .text($0.title) }) { a in
                            V2TableCellText(a.title)
                        },
                        V2DataColumn(id: "rule", title: "Rule", width: .flexible(min: 160),
                                     sortKey: { .text($0.ruleId) }) { a in
                            V2TableCellText(a.ruleId, primary: false, mono: true)
                        },
                        V2DataColumn(id: "when", title: "When", width: .fixed(110),
                                     sortKey: { .date($0.timestamp) }) { a in
                            V2TableCellText(V2TimeFormat.relative(a.timestamp), primary: false)
                        },
                        // Drive the chip off the real disposition — a still-open
                        // alert is no longer mislabeled green "Resolved", and a
                        // set analystStatus (false_positive / dismissed / …) is
                        // honored instead of being flattened to "Resolved".
                        V2DataColumn(id: "status", title: "Status", width: .fixed(120),
                                     sortKey: { .text(historyStatusChip($0).0) }) { a in
                            let chip = historyStatusChip(a)
                            V2StatusChip(chip.0, kind: chip.1)
                        },
                        // History row actions: Unsuppress + Delete.
                        // Pre-fix the History tab was read-only — once
                        // an alert was suppressed there was no way
                        // (without `maccrabctl unsuppress`) to bring
                        // it back. These two row buttons cover the
                        // most common operator fix-ups inline.
                        V2DataColumn(id: "actions", title: "Actions", width: .fixed(170)) { a in
                            // v1.18.1: unified on the shared compact tinted
                            // V2ActionButton (the old hand-rolled pills
                            // predate the .tinted/.compact variants).
                            HStack(spacing: 4) {
                                if a.suppressed {
                                    V2ActionButton(String(localized: "suppression.unsuppress", defaultValue: "Unsuppress"), icon: "bell",
                                                   style: .tinted(V2Theme.brand), size: .compact,
                                                   tooltip: "Lift suppression on this alert") {
                                        Task { await unsuppressAlert(a) }
                                    }
                                }
                                V2ActionButton(String(localized: "alerts.confirmDeleteButton", defaultValue: "Delete"), icon: "trash",
                                               style: .tinted(V2Theme.critical), size: .compact,
                                               tooltip: "Permanently delete this alert from alerts.db") {
                                    // Route through a confirmation — the delete is
                                    // irreversible (hard DELETE incl. snapshotted
                                    // evidence) and sits next to Unsuppress.
                                    pendingDeleteAlert = a
                                }
                            }
                        },
                    ],
                    items: history,
                    selection: .constant(nil)
                )
                .frame(minHeight: 420)
            }
            .padding(16)
        }
    }

    private func unsuppressAlert(_ alert: V2MockAlert) async {
        await submitMutations([.init(operation: .unsuppressAlert, targetID: alert.id, title: alert.title)])
    }

    private func deleteAlert(_ alert: V2MockAlert) async {
        await submitMutations([.init(operation: .deleteAlert, targetID: alert.id, title: alert.title)])
    }

    private var suppressionsTab: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                daemonStaleBanner
                Text(String(localized: "ui.V2AlertsWorkspace.active.suppressions.silence.specific.rule.scope.pairs", defaultValue: "Active suppressions apply to the scopes shown until expiry. Lift requests remove one saved entry; the list changes after the engine confirms removal."))
                    .font(V2Theme.body())
                    .foregroundStyle(V2Theme.mutedText)
                // B6: only assert "no active suppressions" when the engine is
                // actually reporting — on a dead/stale daemon an empty list is
                // a read failure, not a fact. Gate the empty state on
                // daemonReporting (the stale banner above already explains the
                // gap), mirroring the Open + Campaigns tabs.
                if let error = state.provider.suppressionReadError {
                    V2EmptyState(
                        title: String(localized: "alerts.suppressionsUnavailableTitle", defaultValue: "Suppression state unavailable"),
                        body: error, icon: "exclamationmark.triangle"
                    )
                    .v2Panel()
                } else if suppressionEntries.isEmpty && loaded && daemonReporting {
                    V2EmptyState(
                        title: String(localized: "alerts.noActiveSuppressions", defaultValue: "No active suppressions"),
                        body: String(localized: "alerts.noActiveSuppressionsBody", defaultValue: "The engine’s saved snapshot contains no active suppression entries. Alert dispositions are shown separately in the alert lists."),
                        icon: "bell.slash"
                    )
                    .v2Panel()
                } else {
                    V2DataTable(
                        columns: [
                            V2DataColumn(id: "rule", title: "Rule", width: .flexible(min: 200),
                                         sortKey: { .text($0.ruleId) }) { e in
                                V2TableCellText(e.ruleId, mono: true)
                            },
                            V2DataColumn(id: "scope", title: "Scope", width: .flexible(min: 140),
                                         sortKey: { .text($0.scope) }) { e in
                                V2TableCellText(e.scope, primary: false)
                            },
                            V2DataColumn(id: "by", title: "Added by", width: .fixed(110),
                                         sortKey: { .text($0.addedBy) }) { e in
                                V2TableCellText(e.addedBy, primary: false)
                            },
                            V2DataColumn(id: "added", title: "Added", width: .fixed(100),
                                         sortKey: { .date($0.createdAt) }) { e in
                                V2TableCellText(V2TimeFormat.relative(e.createdAt), primary: false)
                            },
                            V2DataColumn(id: "exp", title: "Expires", width: .fixed(100),
                                         // Indefinite (no expiry) sorts last.
                                         sortKey: { .date($0.expiresAt ?? .distantFuture) }) { e in
                                if let exp = e.expiresAt {
                                    V2StatusChip(V2TimeFormat.relative(exp), kind: .neutral)
                                } else {
                                    V2StatusChip(String(localized: "ui.V2AlertsWorkspace.indefinite", defaultValue: "indefinite"), kind: .warning)
                                }
                            },
                            V2DataColumn(id: "lift", title: "", width: .fixed(72)) { e in
                                Button {
                                    Task { await liftSuppression(e) }
                                } label: {
                                    Text(String(localized: "ui.V2AlertsWorkspace.lift", defaultValue: "Lift"))
                                        .font(V2Theme.meta())
                                        .foregroundStyle(V2Theme.dataAccent)
                                        .padding(.horizontal, 10).padding(.vertical, 4)
                                        .overlay(
                                            RoundedRectangle(cornerRadius: V2Theme.smallCornerRadius)
                                                .stroke(V2Theme.dataAccent.opacity(0.4), lineWidth: 1)
                                        )
                                }
                                .buttonStyle(.plain)
                                .help(String(localized: "ui.V2AlertsWorkspace.remove.this.suppression.the.rule.will.fire", defaultValue: "Remove this suppression — the rule will fire again the next time it matches"))
                            },
                        ],
                        items: suppressionEntries,
                        selection: .constant(nil)
                    )
                    .frame(minHeight: 360)
                }
            }
            .padding(16)
        }
    }
}
