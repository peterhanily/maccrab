// V2AlertsWorkspace.swift
// Spec §7.2 — triage, route, and dispose alerts. Severity summary
// + alerts table + selectable inspector with verbs.

import SwiftUI
import AppKit
import UniformTypeIdentifiers

struct V2AlertsWorkspace: View {
    // v1.11.1 (audit perf LOW): hoisted formatter for the JSON-export
    // path so we don't pay ~0.5 ms per alert row to instantiate one.
    nonisolated(unsafe) static let isoFormatter = ISO8601DateFormatter()

    @ObservedObject var state: V2DashboardState
    @ObservedObject var appState: AppState
    @State private var selected: V2MockAlert?
    @State private var suppressionEntries: [V2SuppressionEntry] = []
    @State private var alerts: [V2MockAlert] = []
    @State private var campaigns: [V2MockCampaign] = []
    @State private var selectedCampaignIds: Set<String> = []
    @State private var loaded = false
    // v1.12.7 Wave 9R: pending-mutation reconciliation. After Wave 9Q
    // flipped @State optimistically on click, the auto-refresh-tick
    // reload() — reading directly from alerts.db before the daemon
    // had processed the inbox file — was clobbering the optimistic
    // flip and "flickering" the alert back to its pre-mutation state.
    // These sets track in-flight mutations so reload() can overlay
    // the optimistic value on top of the DB read until the daemon
    // catches up (at which point the set entry is pruned).
    @State private var pendingSuppressedAlertIds: Set<String> = []
    @State private var pendingUnsuppressedAlertIds: Set<String> = []
    @State private var pendingDeletedAlertIds: Set<String> = []
    @State private var pendingSuppressedCampaignIds: Set<String> = []
    @State private var pendingLiftedSuppressionKeys: Set<String> = []

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

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            V2WorkspaceTabStrip(
                tabs: V2Workspace.alerts.tabs,
                selected: Binding(
                    get: { state.selectedTabs[.alerts] ?? .alertsOpen },
                    set: { if let v = $0 { state.selectedTabs[.alerts] = v } }
                )
            )
            tabBody
                .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
        .task(id: "\(state.provider.mode):\(state.refreshTick):\(state.alertTimeRange)") { await reload() }
    }

    private func reload() async {
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

        let a = await state.provider.alerts(limit: 200)
        await MainActor.run {
            // v1.12.7 Wave 9R: overlay pending optimistic mutations
            // on top of the DB read. The daemon's inbox poller has
            // a 5 s cadence so reload() runs at the next refresh tick
            // can race the daemon's apply — without this overlay the
            // pre-mutation DB value would clobber the user's just-
            // clicked optimistic state for one tick (visible flicker).
            // Prune entries whose DB value has caught up to the
            // optimistic value (daemon has applied).
            let merged: [V2MockAlert] = a.compactMap { dbAlert in
                if pendingDeletedAlertIds.contains(dbAlert.id) {
                    // Optimistic delete — hide row until DB drops it.
                    return nil
                }
                var copy = dbAlert
                if pendingSuppressedAlertIds.contains(dbAlert.id) {
                    copy.suppressed = true
                } else if pendingUnsuppressedAlertIds.contains(dbAlert.id) {
                    copy.suppressed = false
                }
                return copy
            }
            // Prune `pendingSuppressedAlertIds` for IDs the DB now
            // reflects as suppressed (daemon caught up).
            pendingSuppressedAlertIds = pendingSuppressedAlertIds.filter { id in
                guard let dbAlert = a.first(where: { $0.id == id }) else { return true }
                return !dbAlert.suppressed
            }
            pendingUnsuppressedAlertIds = pendingUnsuppressedAlertIds.filter { id in
                guard let dbAlert = a.first(where: { $0.id == id }) else { return true }
                return dbAlert.suppressed
            }
            // Pending delete is pruned only when the DB no longer
            // returns the row.
            let dbIds = Set(a.map(\.id))
            pendingDeletedAlertIds = pendingDeletedAlertIds.intersection(dbIds)

            self.alerts = merged.filter { $0.timestamp >= cutoff }
            self.loaded = true
        }

        let c = await state.provider.campaigns(limit: 50)
        await MainActor.run {
            // Same overlay pattern for campaigns: hide optimistically-
            // suppressed campaigns until the DB-side suppress lands.
            let merged = c.filter { !pendingSuppressedCampaignIds.contains($0.id) }
            // Prune: if a campaign no longer appears in c, the daemon
            // has applied (suppressed campaigns drop from the active
            // list returned by `campaigns(limit:)`).
            let dbCampaignIds = Set(c.map(\.id))
            pendingSuppressedCampaignIds = pendingSuppressedCampaignIds.intersection(dbCampaignIds)

            self.campaigns = merged.filter { $0.lastSeen >= cutoff }
        }

        let s = await state.provider.suppressions()
        await MainActor.run {
            // Suppression lifts: hide entries we've optimistically
            // lifted until the DB drops them. Key format matches
            // pendingLiftedSuppressionKeys: "ruleId|scope".
            let merged = s.filter { entry in
                !pendingLiftedSuppressionKeys.contains("\(entry.ruleId)|\(entry.scope)")
            }
            // Prune: a lifted entry whose key no longer appears in s.
            let dbKeys = Set(s.map { "\($0.ruleId)|\($0.scope)" })
            pendingLiftedSuppressionKeys = pendingLiftedSuppressionKeys.intersection(dbKeys)
            self.suppressionEntries = merged
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
        // v1.12.7 Wave 9Q+9R: flip the local suppressed flag and
        // register the pending mutation so subsequent reload()s
        // overlay the optimistic value on top of the DB read until
        // the daemon catches up. Pre-9R the optimistic flip flickered
        // back to un-suppressed on the next reload because the DB
        // still had the old value (daemon hadn't processed inbox).
        await MainActor.run {
            pendingSuppressedAlertIds.insert(alert.id)
            pendingUnsuppressedAlertIds.remove(alert.id)
            if let idx = self.alerts.firstIndex(where: { $0.id == alert.id }) {
                self.alerts[idx].suppressed = true
            }
            selected = nil
        }

        let ok = await state.provider.suppressAlert(id: alert.id)
        await MainActor.run {
            if ok {
                state.showToast(V2Toast(
                    kind: .success,
                    title: "Alert suppressed",
                    detail: alert.ruleId
                ))
            } else {
                // Rollback the optimistic state.
                pendingSuppressedAlertIds.remove(alert.id)
                if let idx = self.alerts.firstIndex(where: { $0.id == alert.id }) {
                    self.alerts[idx].suppressed = false
                }
                let detail = state.provider.lastErrorDescription ?? "unknown error"
                let isReadOnly = detail.lowercased().contains("read-only")
                state.showToast(V2Toast(
                    kind: isReadOnly ? .warning : .error,
                    title: isReadOnly ? "Cannot mutate from dashboard"
                                      : "Suppress failed",
                    detail: detail,
                    displayFor: 6
                ))
            }
        }
        // No trailing reload nor refreshTick bump — the natural
        // 5 s auto-tick will reconcile, and our pending-mutation
        // overlay shields us from the daemon-lag flicker.
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
                    .font(.system(size: 14))
            }
            .buttonStyle(.plain)
            .help(selectedCampaignIds.count == campaigns.count ? "Deselect all" : "Select all campaigns")

            if selectedCampaignIds.isEmpty {
                Text("\(campaigns.count) campaign\(campaigns.count == 1 ? "" : "s") · click to select for bulk-suppress")
                    .font(V2Theme.meta())
                    .foregroundStyle(V2Theme.mutedText)
            } else {
                Text("\(selectedCampaignIds.count) of \(campaigns.count) selected")
                    .font(V2Theme.meta())
                    .foregroundStyle(V2Theme.primaryText)
            }
            Spacer()
            V2ActionButton("Bulk suppress (\(selectedCampaignIds.count))",
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
        // v1.12.7 Wave 9Q+9R: optimistic removal + pending registration.
        let targetIds = Set(targets.map(\.id))
        await MainActor.run {
            pendingSuppressedCampaignIds.formUnion(targetIds)
            self.campaigns.removeAll { targetIds.contains($0.id) }
            self.selectedCampaignIds.removeAll()
        }

        var totalSuppressed = 0
        var failedCount = 0
        for c in targets {
            let count = await state.provider.suppressCampaign(id: c.id)
            if count > 0 {
                totalSuppressed += count
            } else {
                failedCount += 1
                // Read-only DB — abort early; subsequent calls will
                // hit the same error.
                let detail = state.provider.lastErrorDescription ?? ""
                if detail.lowercased().contains("read-only") { break }
            }
        }
        await MainActor.run {
            if failedCount == 0 {
                state.showToast(V2Toast(
                    kind: .success,
                    title: "Bulk suppress",
                    detail: "\(targets.count) campaign\(targets.count == 1 ? "" : "s") · \(totalSuppressed) total item\(totalSuppressed == 1 ? "" : "s")"
                ))
            } else if totalSuppressed > 0 {
                state.showToast(V2Toast(
                    kind: .warning,
                    title: "Partial bulk suppress",
                    detail: "\(targets.count - failedCount) of \(targets.count) campaigns; \(state.provider.lastErrorDescription ?? "see logs")",
                    displayFor: 6
                ))
            } else {
                // Total failure — drop pending registrations so the
                // next reload restores the campaigns.
                pendingSuppressedCampaignIds.subtract(targetIds)
                let detail = state.provider.lastErrorDescription ?? "unknown error"
                let isReadOnly = detail.lowercased().contains("read-only")
                state.showToast(V2Toast(
                    kind: isReadOnly ? .warning : .error,
                    title: isReadOnly ? "Cannot mutate from dashboard"
                                      : "Bulk suppress failed",
                    detail: detail,
                    displayFor: 6
                ))
            }
        }
    }

    /// Layout helper: render a list of strings as wrapped chips. Each
    /// chip is a click target — tap fires the callback.
    @ViewBuilder
    private func FlowingChips(items: [String], kind: V2ChipKind, onTap: @escaping (String) -> Void) -> some View {
        // SwiftUI's HStack doesn't wrap; use a ViewThatFits-fallback
        // FlowLayout once we adopt iOS 16+. For now a simple HStack
        // with .lineLimit(2) handles 4–6 chips fine.
        HStack(spacing: 6) {
            ForEach(items, id: \.self) { tech in
                Button { onTap(tech) } label: {
                    V2StatusChip(tech, kind: kind, icon: "arrow.up.forward")
                }
                .buttonStyle(.plain)
                .help("Open MITRE D3FEND reference for \(tech)")
            }
            Spacer(minLength: 0)
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

    /// Shell out to `maccrabctl unsuppress` and refresh the list.
    /// Uses scope when present so partial suppressions (per-process)
    /// don't accidentally lift the entire rule.
    private func liftSuppression(_ entry: V2SuppressionEntry) async {
        // v1.12.7 Wave 9Q+9R: optimistic removal + pending registration.
        let key = "\(entry.ruleId)|\(entry.scope)"
        await MainActor.run {
            pendingLiftedSuppressionKeys.insert(key)
            self.suppressionEntries.removeAll {
                $0.ruleId == entry.ruleId && $0.scope == entry.scope
            }
        }
        let ok = await state.provider.liftSuppression(ruleId: entry.ruleId, scope: entry.scope)
        await MainActor.run {
            if ok {
                state.showToast(V2Toast(
                    kind: .success,
                    title: "Suppression lifted",
                    detail: "\(entry.ruleId) (\(entry.scope))"
                ))
            } else {
                // Drop pending registration; next reload restores.
                pendingLiftedSuppressionKeys.remove(key)
                state.showToast(V2Toast(
                    kind: .error,
                    title: "Lift failed",
                    detail: state.provider.lastErrorDescription
                        ?? "maccrabctl returned non-zero",
                    displayFor: 6
                ))
            }
        }
    }

    private func suppressCampaign(_ c: V2MockCampaign) async {
        // v1.12.7 Wave 9Q+9R: optimistically remove + register pending.
        await MainActor.run {
            pendingSuppressedCampaignIds.insert(c.id)
            self.campaigns.removeAll { $0.id == c.id }
            self.selectedCampaignIds.remove(c.id)
        }

        let count = await state.provider.suppressCampaign(id: c.id)
        await MainActor.run {
            if count > 0 {
                state.showToast(V2Toast(
                    kind: .success,
                    title: "Campaign suppressed",
                    detail: "\(count) item\(count == 1 ? "" : "s") (campaign + contributors)"
                ))
            } else {
                // Rollback the pending registration so the next reload
                // brings the campaign back. The visible list will
                // restore on the next reload — minor delay acceptable
                // on an error path that's already showing a toast.
                pendingSuppressedCampaignIds.remove(c.id)
                let detail = state.provider.lastErrorDescription ?? "no rows updated"
                let isReadOnly = detail.lowercased().contains("read-only")
                state.showToast(V2Toast(
                    kind: isReadOnly ? .warning : .error,
                    title: isReadOnly ? "Cannot mutate from dashboard"
                                      : "Suppress campaign failed",
                    detail: detail,
                    displayFor: 6
                ))
            }
        }
    }

    private func bulkSuppress(_ targets: [V2MockAlert]) async {
        let ids = targets.filter { !$0.suppressed }.map(\.id)
        guard !ids.isEmpty else { return }

        // v1.12.7 Wave 9Q+9R: optimistic flip + pending registration.
        let idSet = Set(ids)
        await MainActor.run {
            pendingSuppressedAlertIds.formUnion(idSet)
            pendingUnsuppressedAlertIds.subtract(idSet)
            for idx in self.alerts.indices where idSet.contains(self.alerts[idx].id) {
                self.alerts[idx].suppressed = true
            }
        }

        let count = await state.provider.suppressAlerts(ids: ids)
        await MainActor.run {
            if count > 0 && count == ids.count {
                state.showToast(V2Toast(
                    kind: .success,
                    title: "Bulk suppress",
                    detail: "\(count) alert\(count == 1 ? "" : "s") suppressed"
                ))
            } else if count > 0 {
                state.showToast(V2Toast(
                    kind: .warning,
                    title: "Partial bulk suppress",
                    detail: "\(count) of \(ids.count) suppressed; \(state.provider.lastErrorDescription ?? "see logs")",
                    displayFor: 6
                ))
                // Don't roll back partial successes — the reload's
                // overlay will keep the optimistic state until the
                // daemon catches up, and prune the registrations as
                // the DB confirms each one individually.
            } else {
                // Total failure — drop the pending registrations
                // and flip the flags back.
                pendingSuppressedAlertIds.subtract(idSet)
                for idx in self.alerts.indices where idSet.contains(self.alerts[idx].id) {
                    self.alerts[idx].suppressed = false
                }
                let detail = state.provider.lastErrorDescription ?? "no rows updated"
                let isReadOnly = detail.lowercased().contains("read-only")
                state.showToast(V2Toast(
                    kind: isReadOnly ? .warning : .error,
                    title: isReadOnly ? "Cannot mutate from dashboard"
                                      : "Bulk suppress failed",
                    detail: detail,
                    displayFor: 6
                ))
            }
        }
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

    // MARK: - Open tab

    private var openTab: some View {
        // Compute `visible` (filtered + sorted) ONCE here and pass to
        // searchBar + alertsTable. Pre-fix searchBar called
        // filteredAlerts(...) for the bulk-suppress count and
        // alertsTable called it again for the table items — twice the
        // O(N log N) work per body re-eval, which fires on every
        // keystroke in the search field. severityCards previously
        // also called it 5× more (once per severity case); that's
        // now precomputed as a counts dict.
        let visible = filteredAlerts(severity: severityFilter.wrappedValue, applyExternalFilter: true)
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
                timeRangeChips
                severityCards
                searchBarMemoized(visible: visible)
                alertsTableMemoized(items: visible)
            }
            .padding(16)
            .frame(maxWidth: .infinity, maxHeight: .infinity)

            if let alert = selected {
                alertInspector(for: alert)
                    .shadow(color: Color.black.opacity(0.25), radius: 8, x: -4, y: 0)
                    .transition(.move(edge: .trailing).combined(with: .opacity))
            }
        }
        .animation(.easeInOut(duration: 0.18), value: selected?.id)
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
                Button { state.alertTimeRange = key } label: {
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

    private var severityCards: some View {
        // Pre-compute the per-severity counts ONCE here. Pre-fix this
        // called `filteredAlerts(severity: sev, applyExternalFilter: false)`
        // 5× per body re-eval (once per severity case via ForEach), and
        // `filteredAlerts` re-runs `filter + filter? + filter? + sorted`
        // over `self.alerts` (up to 200 rows) each call. Since the
        // searchBar's Bulk-suppress count adds a 6th call, every
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
                    .font(.system(size: 26, weight: .bold))
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
                    .font(.system(size: 12))
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
                V2ActionButton("Clear filter", icon: "xmark", style: .ghost) {
                    severityFilter.wrappedValue = nil
                }
            }
            Spacer()
            V2ActionButton("Bulk suppress (\(visible.count))",
                           icon: "bell.slash", style: .secondary,
                           disabled: visible.isEmpty,
                           tooltip: "Suppress all \(visible.count) alerts currently visible in the table") {
                Task { await bulkSuppress(visible) }
            }
            V2ActionButton("Export (\(visible.count))",
                           icon: "square.and.arrow.up", style: .secondary,
                           disabled: visible.isEmpty,
                           tooltip: "Export visible alerts as JSON Lines") {
                exportAlerts(visible)
            }
        }
    }

    /// Memoized variant of alertsTable. Same column wiring as the
    /// public `alertsTable`; only differs in that the rows come from
    /// the caller (so they aren't recomputed for the table what
    /// searchBar already computed for its bulk-suppress badge).
    private func alertsTableMemoized(items: [V2MockAlert]) -> some View {
        V2DataTable(
            columns: alertsTableColumns,
            items: items,
            selection: $selected
        )
    }

    /// Original entry — left in place because `searchBar` is also
    /// used by the History tab, which doesn't want the memoization
    /// hand-off pattern.
    private var searchBar: some View {
        HStack(spacing: 8) {
            HStack(spacing: 8) {
                Image(systemName: "magnifyingglass")
                    .foregroundStyle(V2Theme.mutedText)
                    .font(.system(size: 12))
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
                V2ActionButton("Clear filter", icon: "xmark", style: .ghost) {
                    severityFilter.wrappedValue = nil
                }
            }
            Spacer()
            let visible = filteredAlerts(severity: severityFilter.wrappedValue, applyExternalFilter: true)
            V2ActionButton("Bulk suppress (\(visible.count))",
                           icon: "bell.slash", style: .secondary,
                           disabled: visible.isEmpty,
                           tooltip: "Suppress all \(visible.count) alerts currently visible in the table") {
                Task { await bulkSuppress(visible) }
            }
            V2ActionButton("Export (\(visible.count))",
                           icon: "square.and.arrow.up", style: .secondary,
                           disabled: visible.isEmpty,
                           tooltip: "Export visible alerts as JSON Lines") {
                exportAlerts(visible)
            }
        }
    }

    private var alertsTable: some View {
        let items = filteredAlerts(severity: severityFilter.wrappedValue, applyExternalFilter: true)
        return V2DataTable(
            columns: alertsTableColumns,
            items: items,
            selection: $selected
        )
        .frame(maxHeight: .infinity)
    }

    /// Shared column definitions used by both `alertsTable` and the
    /// memoized `alertsTableMemoized(items:)`. Building these inline
    /// per body re-eval allocated 6 V2DataColumn structs + their
    /// label closures on every keystroke.
    private var alertsTableColumns: [V2DataColumn<V2MockAlert>] {
        [
            V2DataColumn(id: "sev", title: "Severity", width: .fixed(96)) { a in
                V2StatusChip(a.severity.label, kind: a.severity.chipKind)
            },
            V2DataColumn(id: "title", title: "Alert", width: .flexible(min: 200)) { a in
                VStack(alignment: .leading, spacing: 1) {
                    V2TableCellText(a.title, primary: true, lineLimit: 1)
                    V2TableCellText(a.ruleId, primary: false, mono: true, lineLimit: 1)
                }
            },
            V2DataColumn(id: "process", title: "Process", width: .flexible(min: 120, max: 220)) { a in
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
            V2DataColumn(id: "category", title: "Category", width: .fixed(110)) { a in
                V2TableCellText(a.category, primary: false)
            },
            V2DataColumn(id: "mitre", title: "MITRE", width: .fixed(120)) { a in
                Text(a.mitre.first ?? "—")
                    .font(V2Theme.mono())
                    .foregroundStyle(V2Theme.mutedText)
            },
            V2DataColumn(id: "when", title: "When", width: .fixed(90)) { a in
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
            HStack(spacing: 8) {
                V2StatusChip(alert.severity.label, kind: alert.severity.chipKind)
                ForEach(alert.mitre, id: \.self) { code in
                    V2StatusChip(code, kind: .neutral, icon: "doc.plaintext")
                }
            }
            V2InspectorSection("Description") {
                Text(alert.description)
                    .font(V2Theme.body())
                    .foregroundStyle(V2Theme.primaryText)
                    .fixedSize(horizontal: false, vertical: true)
            }
            V2InspectorSection("Process") {
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
            V2InspectorSection("When") {
                V2InspectorKeyValue("Detected", V2TimeFormat.absolute(alert.timestamp), mono: true)
                V2InspectorKeyValue("Relative", V2TimeFormat.relative(alert.timestamp))
            }
            if !alert.actionsTaken.isEmpty {
                V2InspectorSection("Actions taken") {
                    ForEach(alert.actionsTaken, id: \.self) { act in
                        HStack(spacing: 6) {
                            Image(systemName: "checkmark.circle.fill")
                                .foregroundStyle(V2Theme.healthy)
                                .font(.system(size: 11))
                            Text(act).font(V2Theme.body()).foregroundStyle(V2Theme.primaryText)
                        }
                    }
                }
            }
            // Note: the Remediation (`remediationHint`) and D3FEND
            // (`d3fendTechniques`) inspector sections were removed
            // before v1.10.0 GA — the underlying Alert fields exist
            // on the model but `AlertStore` doesn't persist them
            // (see `Alert.swift:55-57` for the v2-schema-migration
            // TODO). Keeping inspector sections that only ever
            // rendered to nothing was actively confusing; both come
            // back in v1.11 when the metadata_json migration lands.
            if let summary = alert.llmSummary, !summary.isEmpty {
                V2InspectorSection("AI analysis") {
                    VStack(alignment: .leading, spacing: 6) {
                        HStack(spacing: 6) {
                            if let v = alert.llmVerdict {
                                V2StatusChip(v.replacingOccurrences(of: "_", with: " "),
                                             kind: verdictChipKind(v))
                            }
                            if let c = alert.llmConfidence {
                                Text("\(Int(c * 100))% confidence")
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
                            Text("Suggested actions:")
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
                                        .font(.system(size: 11))
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
            // Analyst workflow section (status / owner / ticket /
            // notes) removed before v1.10.0 GA — same reason as the
            // Remediation / D3FEND sections above. Returns in v1.11
            // alongside the metadata_json schema column and the
            // inline mutation UI to populate it.
            V2InspectorSection("Surrounding events (±2 min)") {
                surroundingEventsList(for: alert)
            }
            V2InspectorSection("Trace context") {
                VStack(alignment: .leading, spacing: 6) {
                    Text("Inspect this alert's full causal trace via the CLI:")
                        .font(V2Theme.meta())
                        .foregroundStyle(V2Theme.mutedText)
                    HStack(spacing: 6) {
                        Text("maccrabctl trace from-alert \(alert.id)")
                            .font(V2Theme.mono())
                            .foregroundStyle(V2Theme.primaryText)
                            .textSelection(.enabled)
                            .lineLimit(1)
                            .truncationMode(.middle)
                        Spacer()
                        V2ActionButton("Copy", icon: "doc.on.doc", style: .ghost) {
                            NSPasteboard.general.clearContents()
                            NSPasteboard.general.setString("maccrabctl trace from-alert \(alert.id)", forType: .string)
                            state.showToast(V2Toast(kind: .success, title: "Command copied", detail: nil))
                        }
                    }
                }
            }
            V2InspectorSection("Actions") {
                VStack(alignment: .leading, spacing: 8) {
                    V2ActionButton("Investigate in Events", icon: "magnifyingglass", style: .primary) {
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
                    .frame(maxWidth: .infinity, alignment: .leading)
                    V2ActionButton("Open rule", icon: "shield.lefthalf.filled", style: .secondary,
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
                    .frame(maxWidth: .infinity, alignment: .leading)
                    V2ActionButton("Suppress", icon: "bell.slash", style: .secondary,
                                   disabled: alert.suppressed,
                                   tooltip: alert.suppressed
                                        ? "Already suppressed"
                                        : "Mark this alert as suppressed in the alert store") {
                        Task { await suppress(alert) }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
    }

    /// List up to 8 events from AppState.events whose timestamp is
    /// within ±2 minutes of the alert. AppState already polls a
    /// recent window of events from EventStore, so this is a free
    /// in-memory filter — no extra DB round-trip.
    @ViewBuilder
    private func surroundingEventsList(for alert: V2MockAlert) -> some View {
        let window: TimeInterval = 120
        let lo = alert.timestamp.addingTimeInterval(-window)
        let hi = alert.timestamp.addingTimeInterval(+window)
        let nearby = appState.events
            .filter { $0.timestamp >= lo && $0.timestamp <= hi }
            .sorted { $0.timestamp < $1.timestamp }
            .prefix(8)
        if nearby.isEmpty {
            Text("No events from the in-memory window match. Open the Events workspace and zoom to the alert's timestamp for the full surrounding context.")
                .font(V2Theme.meta())
                .foregroundStyle(V2Theme.mutedText)
        } else {
            VStack(alignment: .leading, spacing: 4) {
                ForEach(Array(nearby), id: \.id) { ev in
                    HStack(alignment: .top, spacing: 6) {
                        Text(V2TimeFormat.short(ev.timestamp))
                            .font(V2Theme.mono())
                            .foregroundStyle(V2Theme.tertiaryText)
                            .frame(width: 70, alignment: .leading)
                        Text(ev.processName)
                            .font(V2Theme.body())
                            .foregroundStyle(V2Theme.primaryText)
                            .lineLimit(1)
                        Spacer()
                        Text(ev.category.rawValue)
                            .font(V2Theme.meta())
                            .foregroundStyle(V2Theme.mutedText)
                    }
                }
            }
        }
    }

    // MARK: - Other tabs

    private var campaignsTab: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                timeRangeChips
                if !campaigns.isEmpty {
                    campaignsToolbar
                }
                if campaigns.isEmpty && loaded {
                    V2EmptyState(
                        title: "No active campaigns",
                        body: "MacCrab has not detected any multi-step attack campaigns in the selected time range.",
                        icon: "flame"
                    )
                    .frame(minHeight: 280)
                    .v2Panel()
                } else {
                    ForEach(campaigns) { campaign in
                        campaignCard(campaign)
                    }
                }
            }
            .padding(16)
        }
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
                        .font(.system(size: 16))
                }
                .buttonStyle(.plain)
                .help(isSelected ? "Deselect this campaign" : "Select for bulk-suppress")
                ZStack {
                    RoundedRectangle(cornerRadius: 8)
                        .fill(c.severity.chipKind.color.opacity(0.18))
                    Image(systemName: "flame.fill")
                        .foregroundStyle(c.severity.chipKind.color)
                        .font(.system(size: 18, weight: .bold))
                }
                .frame(width: 40, height: 40)
                VStack(alignment: .leading, spacing: 2) {
                    Text(c.name)
                        .font(.system(size: 15, weight: .semibold))
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
                V2ActionButton("Investigate", icon: "magnifyingglass", style: .secondary) {
                    // Filter the Alerts Open list to this campaign's
                    // contributing rule pattern so the user actually
                    // sees the alerts that built it. The campaign's
                    // ruleTitle is the most stable lookup key (campaign
                    // id is a UUID; tactics are too broad).
                    state.alertSearchQuery = c.name
                    state.alertSeverityFilter = nil
                    state.goto(V2NavigationDestination(
                        workspace: .alerts, tab: .alertsOpen
                    ))
                }
                V2ActionButton("Suppress", icon: "bell.slash", style: .secondary,
                               tooltip: "Suppress this campaign and every contributing alert. Use `maccrabctl unsuppress <rule_id>` to reverse.") {
                    Task { await suppressCampaign(c) }
                }
            }
            Text(c.summary)
                .font(V2Theme.body())
                .foregroundStyle(V2Theme.neutral)
                .fixedSize(horizontal: false, vertical: true)
            HStack(spacing: 6) {
                Text("Tactics:").font(V2Theme.cardTitle()).foregroundStyle(V2Theme.tertiaryText)
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
                            .font(.system(size: 9))
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
                        Text("+\(values.count - cap) more")
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
                timeRangeChips
                Text("Resolved + suppressed alerts from the recent retention window. Right-click a row for Unsuppress and Delete actions, or use the inspector buttons.")
                    .font(V2Theme.body())
                    .foregroundStyle(V2Theme.mutedText)
                let history = self.alerts.filter { $0.suppressed } + self.alerts.suffix(4)
                V2DataTable(
                    columns: [
                        V2DataColumn(id: "sev", title: "Severity", width: .fixed(96)) { a in
                            V2StatusChip(a.severity.label, kind: a.severity.chipKind)
                        },
                        V2DataColumn(id: "title", title: "Alert", width: .flexible(min: 240)) { a in
                            V2TableCellText(a.title)
                        },
                        V2DataColumn(id: "rule", title: "Rule", width: .flexible(min: 160)) { a in
                            V2TableCellText(a.ruleId, primary: false, mono: true)
                        },
                        V2DataColumn(id: "when", title: "When", width: .fixed(110)) { a in
                            V2TableCellText(V2TimeFormat.relative(a.timestamp), primary: false)
                        },
                        V2DataColumn(id: "status", title: "Status", width: .fixed(110)) { a in
                            V2StatusChip(a.suppressed ? "Suppressed" : "Resolved",
                                         kind: a.suppressed ? .neutral : .healthy)
                        },
                        // History row actions: Unsuppress + Delete.
                        // Pre-fix the History tab was read-only — once
                        // an alert was suppressed there was no way
                        // (without `maccrabctl unsuppress`) to bring
                        // it back. These two row buttons cover the
                        // most common operator fix-ups inline.
                        V2DataColumn(id: "actions", title: "Actions", width: .fixed(170)) { a in
                            HStack(spacing: 4) {
                                if a.suppressed {
                                    Button {
                                        Task { await unsuppressAlert(a) }
                                    } label: {
                                        HStack(spacing: 3) {
                                            Image(systemName: "bell")
                                                .font(.system(size: 9, weight: .semibold))
                                            Text("Unsuppress")
                                                .font(V2Theme.meta())
                                        }
                                        .foregroundStyle(V2Theme.brand)
                                        .padding(.horizontal, 6).padding(.vertical, 3)
                                        .background(V2Theme.brand.opacity(0.10))
                                        .clipShape(RoundedRectangle(cornerRadius: 4))
                                    }
                                    .buttonStyle(.plain)
                                    .help("Lift suppression on this alert")
                                }
                                Button {
                                    Task { await deleteAlert(a) }
                                } label: {
                                    HStack(spacing: 3) {
                                        Image(systemName: "trash")
                                            .font(.system(size: 9, weight: .semibold))
                                        Text("Delete")
                                            .font(V2Theme.meta())
                                    }
                                    .foregroundStyle(V2Theme.critical)
                                    .padding(.horizontal, 6).padding(.vertical, 3)
                                    .background(V2Theme.critical.opacity(0.10))
                                    .clipShape(RoundedRectangle(cornerRadius: 4))
                                }
                                .buttonStyle(.plain)
                                .help("Permanently delete this alert from alerts.db")
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
        // v1.12.7 Wave 9Q+9R: flip + pending registration.
        await MainActor.run {
            pendingUnsuppressedAlertIds.insert(alert.id)
            pendingSuppressedAlertIds.remove(alert.id)
            if let idx = self.alerts.firstIndex(where: { $0.id == alert.id }) {
                self.alerts[idx].suppressed = false
            }
        }
        let ok = await state.provider.unsuppressAlert(id: alert.id)
        if ok {
            state.showToast(V2Toast(
                kind: .success,
                title: "Unsuppressed",
                detail: alert.title
            ))
        } else {
            // Rollback the pending registration and flag.
            await MainActor.run {
                pendingUnsuppressedAlertIds.remove(alert.id)
                if let idx = self.alerts.firstIndex(where: { $0.id == alert.id }) {
                    self.alerts[idx].suppressed = true
                }
            }
            state.showToast(V2Toast(
                kind: .error,
                title: "Couldn't unsuppress",
                detail: state.provider.lastErrorDescription
            ))
        }
    }

    private func deleteAlert(_ alert: V2MockAlert) async {
        // v1.12.7 Wave 9Q+9R: remove + pending registration.
        await MainActor.run {
            pendingDeletedAlertIds.insert(alert.id)
            self.alerts.removeAll { $0.id == alert.id }
            if self.selected?.id == alert.id { self.selected = nil }
        }
        let ok = await state.provider.deleteAlert(id: alert.id)
        if ok {
            state.showToast(V2Toast(
                kind: .success,
                title: "Deleted",
                detail: alert.title
            ))
        } else {
            // Drop the pending delete; next reload restores the row.
            await MainActor.run { pendingDeletedAlertIds.remove(alert.id) }
            state.showToast(V2Toast(
                kind: .error,
                title: "Couldn't delete",
                detail: state.provider.lastErrorDescription
            ))
        }
    }

    private var suppressionsTab: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                Text("Active suppressions silence specific (rule, scope) pairs until expiry. Lift a suppression with the per-row button — the daemon's SuppressionManager re-evaluates immediately.")
                    .font(V2Theme.body())
                    .foregroundStyle(V2Theme.mutedText)
                if suppressionEntries.isEmpty && loaded {
                    V2EmptyState(
                        title: "No active suppressions",
                        body: "When you suppress an alert from the Open tab (Actions → Suppress), it appears here as an entry. The list is read from the daemon's `suppressions.json` on every refresh.",
                        icon: "bell.slash"
                    )
                    .v2Panel()
                } else {
                    V2DataTable(
                        columns: [
                            V2DataColumn(id: "rule", title: "Rule", width: .flexible(min: 200)) { e in
                                V2TableCellText(e.ruleId, mono: true)
                            },
                            V2DataColumn(id: "scope", title: "Scope", width: .flexible(min: 140)) { e in
                                V2TableCellText(e.scope, primary: false)
                            },
                            V2DataColumn(id: "by", title: "Added by", width: .fixed(110)) { e in
                                V2TableCellText(e.addedBy, primary: false)
                            },
                            V2DataColumn(id: "added", title: "Added", width: .fixed(100)) { e in
                                V2TableCellText(V2TimeFormat.relative(e.createdAt), primary: false)
                            },
                            V2DataColumn(id: "exp", title: "Expires", width: .fixed(100)) { e in
                                if let exp = e.expiresAt {
                                    V2StatusChip(V2TimeFormat.relative(exp), kind: .neutral)
                                } else {
                                    V2StatusChip("indefinite", kind: .warning)
                                }
                            },
                            V2DataColumn(id: "lift", title: "", width: .fixed(72)) { e in
                                Button {
                                    Task { await liftSuppression(e) }
                                } label: {
                                    Text("Lift")
                                        .font(V2Theme.meta())
                                        .foregroundStyle(V2Theme.dataAccent)
                                        .padding(.horizontal, 10).padding(.vertical, 4)
                                        .overlay(
                                            RoundedRectangle(cornerRadius: V2Theme.smallCornerRadius)
                                                .stroke(V2Theme.dataAccent.opacity(0.4), lineWidth: 1)
                                        )
                                }
                                .buttonStyle(.plain)
                                .help("Remove this suppression — the rule will fire again the next time it matches")
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
