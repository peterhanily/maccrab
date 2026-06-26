// V2OverviewWorkspace.swift
// Spec §7.1 — single-screen operational summary. No tabs.

import SwiftUI
import MacCrabCore
import MacCrabForensics
import UniformTypeIdentifiers

struct V2OverviewWorkspace: View {

    @ObservedObject var state: V2DashboardState
    @ObservedObject var appState: AppState
    @State private var alerts: [V2MockAlert] = []
    @State private var campaigns: [V2MockCampaign] = []
    @State private var kpis: V2OverviewKPIs = .zero
    @State private var histogramBuckets: [V2OverviewBucket] = []
    @State private var rangeKey: String = "6h"
    @State private var showingSecurityFactors: Bool = false
    // Issue #2: surface forensics/plugins on Overview.
    @State private var forensicsBuiltinCount = 0
    @State private var forensicsInstalledCount = 0
    @State private var forensicsLastScan: CaseManifest? = nil
    @State private var lastForensicsCardToken: Date? = nil   // PERF-1: mtime gate
    // Click-to-explain: which security factor row is expanded to its guidance.
    @State private var expandedFactorName: String? = nil
    // Store news on the forensics/plugins card.
    @State private var storeNews: [StoreNewsItem] = []
    // Customizable dashboard: which widgets show, in what order, at what size.
    @StateObject private var layout = V2OverviewLayoutStore()
    @State private var editing = false
    @State private var draggingID: String? = nil
    @State private var dropTargeted = false   // drag is over the dashboard area

    init(state: V2DashboardState, appState: AppState) {
        self.state = state
        self.appState = appState
    }

    private var securityGradeTrendKind: V2ChipKind {
        if appState.securityScore == 0 { return .neutral }
        if appState.securityScore >= 90 { return .healthy }
        if appState.securityScore >= 75 { return .info }
        if appState.securityScore >= 60 { return .warning }
        return .high
    }

    private var securityGradeIconColor: Color {
        if appState.securityScore == 0 { return V2Theme.mutedText }
        if appState.securityScore >= 75 { return V2Theme.healthy }
        if appState.securityScore >= 60 { return V2Theme.warning }
        return V2Theme.high
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 12) {
                customizeToolbar
                // Protection status is pinned: a security tool should never let
                // the user hide whether they're protected.
                protectionBanner
                // Everything else is a movable / resizable / hideable widget.
                V2FlowGridLayout(columns: 4, spacing: 8, rowSpacing: 12) {
                    ForEach(layout.visibleOrdered) { entry in
                        V2OverviewWidgetTile(widget: entry.widget, editing: editing,
                                             store: layout, draggingID: $draggingID) {
                            renderWidget(entry.widget)
                        }
                        .widgetSpan(entry.span)
                    }
                }
                if layout.allHidden {
                    // Keep the dashboard recoverable even outside edit mode — point
                    // the user at Customize → Add widget rather than show a blank area.
                    Text(editing
                         ? String(localized: "overview.customize.allHidden",
                                   defaultValue: "All widgets are hidden. Use “Add widget” to bring some back.")
                         : String(localized: "overview.customize.allHiddenIdle",
                                   defaultValue: "All widgets are hidden. Open “Customize” to add some back."))
                        .font(V2Theme.body()).foregroundStyle(V2Theme.mutedText)
                        .frame(maxWidth: .infinity, alignment: .center).padding(.vertical, 24)
                }
            }
            .padding(16)
            // Catch drops that land in gaps between cards. Persist once at drag-end.
            .onDrop(of: [UTType.text], isTargeted: $dropTargeted) { _ in
                draggingID = nil
                layout.commit()
                return false
            }
            // When the drag leaves the dashboard (e.g. released outside the
            // window) clear the dragging state, otherwise a card could stay
            // stuck faded. Persist wherever the reorder ended up.
            .onChange(of: dropTargeted) { targeted in
                if !targeted && draggingID != nil {
                    draggingID = nil
                    layout.commit()
                }
            }
        }
        .sheet(isPresented: $showingSecurityFactors) {
            securityFactorsSheet
        }
        .task(id: "\(state.provider.mode):\(state.refreshTick):\(rangeKey)") {
            // v1.12.6 Wave 9P: write each field to @State as soon as
            // its async load resolves, rather than batching all four
            // into one trailing MainActor.run. Pre-9P on a host with
            // a big alerts.db, the sequential awaits (esp. kpis()
            // which fans out to 5 SQL queries and alertHistogram()
            // which scans up to 10K rows) could exceed the 5s
            // auto-refresh tick. When state.refreshTick incremented,
            // `.task(id:)` cancelled the body mid-await — the final
            // MainActor.run never ran, the user saw permanently
            // stale alerts/campaigns/KPIs/histogram until they
            // closed and reopened the dashboard (which reset
            // refreshTick to 0). Wave 9G fixed the same shape in
            // V2IntelligenceWorkspace; 9P extends to Overview /
            // Alerts / System.
            let a = await state.provider.alerts(limit: 50)
            await MainActor.run { self.alerts = a }

            let c = await state.provider.campaigns(limit: 20)
            await MainActor.run { self.campaigns = c }

            let k = await state.provider.kpis()
            await MainActor.run { self.kpis = k }

            let buckets = await state.provider.alertHistogram(rangeKey: rangeKey)
            await MainActor.run { self.histogramBuckets = buckets }

            // Populate the AI Guard + Threat Intel tiles (both @Published on
            // appState; mtime-gated so a tight refresh tick is cheap).
            await appState.refreshThreatIntelStats()
            await appState.refreshAgentLineage()
            await loadForensicsCard()
        }
    }

    /// Three-state banner driven by real signals: protection-active
    /// (live data + heartbeat fresh + score ≥ 75), degraded (live but
    /// score < 75 or stale heartbeat), or inactive (mock-mode = no
    /// daemon writing data). v1.12.0 RC16: dropped the .starting state
    /// (briefly introduced in RC15) — turbo-fast daemon boot makes the
    /// transient "starting" window invisible to the user, so the extra
    /// state was just noise.
    private enum ProtectionState { case active, degraded, inactive }

    private var protectionState: ProtectionState {
        // Not live (offline/no-daemon in release, or mock in DEBUG) ⇒ inactive.
        if state.provider.mode != .live { return .inactive }
        let heartbeatFresh: Bool = {
            guard let hb = appState.heartbeat else { return false }
            return !hb.isStale
        }()
        if !heartbeatFresh { return .degraded }
        if appState.isProtectionDegraded { return .degraded }
        if appState.securityScore > 0 && appState.securityScore < 75 { return .degraded }
        return .active
    }

    private var protectionBanner: some View {
        let s = protectionState
        let title: String = {
            switch s {
            case .active:   return String(localized: "overview.bannerTitleActive", defaultValue: "Protected — system is secure")
            case .degraded: return String(localized: "overview.bannerTitleDegraded", defaultValue: "Protection degraded — review System Health")
            case .inactive: return String(localized: "overview.bannerTitleInactive", defaultValue: "Protection inactive — daemon not detected")
            }
        }()
        let body: String = {
            switch s {
            case .active:
                let collectors = appState.heartbeat?.collectorHealth?.count ?? 0
                return collectors == 0
                    ? String(localized: "overview.bannerBodyActiveNoCount", defaultValue: "Live data flowing · collectors active")
                    : String(localized: "overview.bannerBodyActive", defaultValue: "Live data flowing · \(collectors) collectors active")
            case .degraded:
                return String(localized: "overview.bannerBodyDegraded", defaultValue: "Live data is stale or score is low — open System health for details")
            case .inactive:
                return String(localized: "overview.bannerBodyInactive", defaultValue: "Start the System Extension or run `swift run maccrabd` to begin protection")
            }
        }()
        let color: Color = {
            switch s {
            case .active:   return V2Theme.healthy
            case .degraded: return V2Theme.warning
            case .inactive: return V2Theme.high
            }
        }()
        let icon: String = {
            switch s {
            case .active:   return "checkmark.shield.fill"
            case .degraded: return "exclamationmark.shield.fill"
            case .inactive: return "xmark.shield.fill"
            }
        }()
        return Button {
            state.goto(V2NavigationDestination(workspace: .system, tab: .systemHealth))
        } label: {
            HStack(spacing: 12) {
                ZStack {
                    Circle()
                        .fill(color.opacity(0.25))
                        .frame(width: 38, height: 38)
                    Image(systemName: icon)
                        .foregroundStyle(color)
                        .scaledSystem(18, weight: .bold)
                }
                VStack(alignment: .leading, spacing: 1) {
                    Text(title)
                        .scaledSystem(14, weight: .semibold)
                        .foregroundStyle(V2Theme.primaryText)
                    Text(body)
                        .font(V2Theme.meta())
                        .foregroundStyle(V2Theme.primaryText.opacity(0.7))
                }
                Spacer()
                Image(systemName: "chevron.forward")
                    .scaledSystem(11, weight: .semibold)
                    .foregroundStyle(V2Theme.primaryText.opacity(0.5))
            }
            .padding(.horizontal, 14)
            .padding(.vertical, 11)
            .background(
                LinearGradient(
                    colors: [color.opacity(0.20), color.opacity(0.10)],
                    startPoint: .leading, endPoint: .trailing
                )
            )
            .overlay(
                RoundedRectangle(cornerRadius: V2Theme.cornerRadius)
                    .stroke(color.opacity(0.40), lineWidth: 1)
            )
            .clipShape(RoundedRectangle(cornerRadius: V2Theme.cornerRadius))
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }

    // MARK: - Customizable layout

    /// Top-right controls: enter Customize mode, or (while editing) add hidden
    /// widgets back, reset to defaults, and finish.
    private var customizeToolbar: some View {
        HStack(spacing: 8) {
            if editing {
                Label(String(localized: "overview.customize.hint",
                             defaultValue: "Drag a card to rearrange · use the controls on each card to resize or hide it"),
                      systemImage: "hand.draw")
                    .labelStyle(.titleAndIcon)
                    .font(V2Theme.meta())
                    .foregroundStyle(V2Theme.mutedText)
                    .lineLimit(1).truncationMode(.tail)
            }
            Spacer()
            if editing {
                if !layout.hiddenWidgets.isEmpty {
                    Menu {
                        ForEach(layout.hiddenWidgets, id: \.self) { w in
                            Button(w.displayName) { withAnimation { layout.show(w.rawValue) } }
                        }
                    } label: {
                        Label(String(localized: "overview.customize.add", defaultValue: "Add widget"), systemImage: "plus")
                            .font(V2Theme.meta())
                    }
                    .menuStyle(.borderlessButton)
                    .fixedSize()
                }
                Button(String(localized: "overview.customize.reset", defaultValue: "Reset")) {
                    withAnimation { layout.reset() }
                }
                .buttonStyle(.bordered).controlSize(.small)
                Button(String(localized: "overview.customize.done", defaultValue: "Done")) {
                    draggingID = nil
                    withAnimation { editing = false }
                }
                .buttonStyle(.borderedProminent).controlSize(.small)
            } else {
                Button { withAnimation { editing = true } } label: {
                    Label(String(localized: "overview.customize.button", defaultValue: "Customize"), systemImage: "slider.horizontal.3")
                        .font(V2Theme.meta())
                }
                .buttonStyle(.bordered).controlSize(.small)
                .help(String(localized: "overview.customize.help", defaultValue: "Show, hide, resize and rearrange dashboard widgets"))
            }
        }
    }

    @ViewBuilder
    private func renderWidget(_ widget: V2OverviewWidget) -> some View {
        switch widget {
        case .kpiSecurityGrade:   securityGradeTile
        case .kpiOpenAlerts:      openAlertsTile
        case .kpiActiveCampaigns: activeCampaignsTile
        case .kpiAIGuard:         aiGuardTile
        case .kpiEventRate:       eventRateTile
        case .kpiThreatIntel:     threatIntelTile
        case .alertHistogram:     postureTimelineCard
        case .recentActivity:     recentActivityCard
        case .quickActions:       quickActionsCard
        case .forensics:          forensicsCard
        }
    }

    // MARK: - KPI tiles (each an independent, movable/resizable widget)

    /// Uniform tile sizing so KPI cards keep their shape and fill their grid cell.
    private func kpiTile<V: View>(_ card: V) -> some View {
        card.frame(maxWidth: .infinity, minHeight: 124, maxHeight: 124)
    }

    private var securityGradeTile: some View {
        kpiTile(V2KpiCard(
            title: String(localized: "overview.kpiSecurityGrade", defaultValue: "Security Grade"),
            value: appState.securityGrade.isEmpty ? "—" : appState.securityGrade,
            trend: appState.securityScore == 0 ? String(localized: "overview.kpiScoring", defaultValue: "scoring…") : "\(appState.securityScore) / 100",
            trendKind: securityGradeTrendKind,
            icon: "checkmark.seal.fill",
            iconColor: securityGradeIconColor,
            footer: appState.securityFactors.isEmpty
                ? String(localized: "overview.kpiPostureFooter", defaultValue: "Live system posture (SIP, FileVault, firewall, etc.)")
                : String(localized: "overview.kpiChecksPass", defaultValue: "\(appState.securityFactors.filter { $0.status == "pass" }.count) of \(appState.securityFactors.count) checks pass"),
            action: V2KpiAction(String(localized: "overview.kpiViewFactors", defaultValue: "View factors")) {
                showingSecurityFactors = true
            }
        ))
    }

    private var openAlertsTile: some View {
        kpiTile(V2KpiCard(
            title: String(localized: "overview.kpiOpenAlerts", defaultValue: "Open Alerts"),
            value: "\(kpis.openAlerts24h)",
            trend: openAlertsTrendLabel,
            trendKind: openAlertsTrendKind,
            icon: "bell.fill",
            iconColor: V2Theme.high,
            action: V2KpiAction(String(localized: "overview.kpiViewAlerts", defaultValue: "View Alerts")) {
                state.goto(V2NavigationDestination(workspace: .alerts, tab: .alertsOpen))
            },
            visual: kpis.eventsLast8Buckets.isEmpty
                ? nil
                : .sparkline(values: kpis.eventsLast8Buckets, color: V2Theme.high)
        ))
    }

    private var activeCampaignsTile: some View {
        kpiTile(V2KpiCard(
            title: String(localized: "overview.kpiActiveCampaigns", defaultValue: "Active Campaigns"),
            value: "\(kpis.activeCampaigns)",
            trend: campaignTrendLabel,
            trendKind: kpis.activeCampaignsCritical > 0 ? .critical
                : kpis.activeCampaignsHigh > 0 ? .high : .info,
            icon: "flame.fill",
            iconColor: kpis.activeCampaignsCritical > 0 ? V2Theme.critical : V2Theme.high,
            action: V2KpiAction(String(localized: "overview.kpiViewCampaigns", defaultValue: "View Campaigns")) {
                state.goto(V2NavigationDestination(workspace: .alerts, tab: .alertsCampaigns))
            }
        ))
    }

    private var aiGuardTile: some View {
        kpiTile(V2KpiCard(
            title: String(localized: "overview.kpiAIGuard", defaultValue: "AI Guard"),
            value: aiGuardValue,
            trend: aiGuardTrend,
            trendKind: aiGuardTrendKind,
            icon: "brain.head.profile",
            iconColor: V2Theme.aiAccent,
            action: V2KpiAction(String(localized: "overview.kpiViewAIGuard", defaultValue: "View AI Guard")) {
                state.goto(V2NavigationDestination(
                    workspace: .detection, tab: .detectionAIGuard
                ))
            }
        ))
    }

    private var eventRateTile: some View {
        kpiTile(V2KpiCard(
            title: String(localized: "overview.kpiEventRate", defaultValue: "Event Rate"),
            value: formatRate(kpis.eventsPerSecond),
            trend: String(localized: "overview.kpiEventRateTrend", defaultValue: "/sec · last 1m"),
            trendKind: .info,
            icon: "waveform.path",
            iconColor: V2Theme.dataAccent,
            action: V2KpiAction(String(localized: "overview.kpiViewEvents", defaultValue: "View Events")) {
                state.goto(V2NavigationDestination(
                    workspace: .events, tab: nil
                ))
            },
            visual: kpis.eventsLast8Buckets.isEmpty
                ? nil
                : .bars(values: kpis.eventsLast8Buckets, color: V2Theme.dataAccent)
        ))
    }

    private var threatIntelTile: some View {
        kpiTile(V2KpiCard(
            title: String(localized: "overview.kpiThreatIntel", defaultValue: "Threat Intel"),
            value: threatIntelValue,
            trend: threatIntelTrend,
            trendKind: threatIntelTrendKind,
            icon: "globe.americas.fill",
            iconColor: V2Theme.dataAccent,
            action: V2KpiAction(String(localized: "overview.kpiViewIntelligence", defaultValue: "View Intelligence")) {
                state.goto(V2NavigationDestination(
                    workspace: .intelligence, tab: .intelligenceThreatIntel
                ))
            }
        ))
    }

    private func formatRate(_ rate: Double) -> String {
        if rate >= 1000 { return String(format: "%.1fK", rate / 1000) }
        if rate >= 10   { return String(format: "%.0f", rate) }
        return String(format: "%.1f", rate)
    }

    private func compactCount(_ n: Int) -> String {
        if n >= 1_000_000 { return String(format: "%.1fM", Double(n) / 1_000_000) }
        if n >= 1_000     { return String(format: "%.1fk", Double(n) / 1_000) }
        return "\(n)"
    }
    private var threatIntelTotal: Int {
        let s = appState.threatIntelStats
        return s.hashes + s.ips + s.domains + s.urls
    }
    private var threatIntelValue: String { threatIntelTotal > 0 ? compactCount(threatIntelTotal) : "—" }
    private var threatIntelTrend: String {
        guard threatIntelTotal > 0 else { return String(localized: "overview.intelNoIndicators", defaultValue: "no indicators loaded") }
        guard let updated = appState.threatIntelStats.lastUpdate else { return String(localized: "overview.intelLoaded", defaultValue: "indicators loaded") }
        let rel = RelativeDateTimeFormatter()
        rel.unitsStyle = .abbreviated
        return String(localized: "overview.intelUpdated", defaultValue: "updated \(rel.localizedString(for: updated, relativeTo: Date()))")
    }
    private var threatIntelTrendKind: V2ChipKind {
        guard threatIntelTotal > 0 else { return .neutral }
        guard let updated = appState.threatIntelStats.lastUpdate else { return .neutral }
        // 6h freshness ceiling, matching V2LiveDataProvider's staleness rule.
        return Date().timeIntervalSince(updated) < 6 * 3600 ? .healthy : .warning
    }

    private var openAlertsTrendLabel: String {
        let d = kpis.openAlertsLast24hDelta
        if d == 0 { return String(localized: "overview.openAlertsNoChange", defaultValue: "no change vs prior 24h") }
        return d > 0 ? String(localized: "overview.openAlertsUp", defaultValue: "+\(d) vs prior 24h") : String(localized: "overview.openAlertsDown", defaultValue: "\(d) vs prior 24h")
    }
    private var openAlertsTrendKind: V2ChipKind {
        kpis.openAlertsLast24hDelta > 0 ? .warning : .healthy
    }
    private var campaignTrendLabel: String {
        if kpis.activeCampaigns == 0 { return String(localized: "overview.campaignsNoneActive", defaultValue: "none active") }
        var parts: [String] = []
        if kpis.activeCampaignsCritical > 0 { parts.append(String(localized: "overview.campaignsCritical", defaultValue: "\(kpis.activeCampaignsCritical) critical")) }
        if kpis.activeCampaignsHigh > 0     { parts.append(String(localized: "overview.campaignsHigh", defaultValue: "\(kpis.activeCampaignsHigh) high")) }
        if kpis.activeCampaignsMedium > 0   { parts.append(String(localized: "overview.campaignsMedium", defaultValue: "\(kpis.activeCampaignsMedium) medium")) }
        return parts.isEmpty ? String(localized: "overview.campaignsActive", defaultValue: "active") : parts.joined(separator: " · ")
    }
    // MARK: - AI Guard tile (bound to live AppState)

    private var aiGuardValue: String { "\(appState.aiSessions.count)" }
    private var aiGuardTrend: String {
        let n = appState.aiSessions.count
        return n == 0 ? String(localized: "overview.aiNoSessions", defaultValue: "no agent sessions") : (n == 1 ? String(localized: "overview.aiSessionSingular", defaultValue: "agent session") : String(localized: "overview.aiSessionPlural", defaultValue: "agent sessions"))
    }
    private var aiGuardTrendKind: V2ChipKind { appState.aiSessions.isEmpty ? .neutral : .ai }

    private var postureTimelineCard: some View {
        let buckets = histogramBuckets
        let total = buckets.reduce(0) { $0 + $1.total }
        return VStack(alignment: .leading, spacing: 10) {
            HStack {
                Text(String(localized: "overview.alertVolumeTitle", defaultValue: "Alert volume — last \(rangeKey)"))
                    .font(V2Theme.sectionTitle()).foregroundStyle(V2Theme.primaryText)
                Text(String(localized: "overview.alertVolumeTotal", defaultValue: "· \(total) total"))
                    .font(V2Theme.meta()).foregroundStyle(V2Theme.mutedText)
                Spacer()
                HStack(spacing: 4) {
                    ForEach(["1h", "6h", "24h", "7d"], id: \.self) { key in
                        rangeChip(key)
                    }
                }
            }
            V2AlertHistogram(
                rangeKey: rangeKey,
                buckets: buckets,
                onBucketTap: { bucket in
                    state.goto(V2NavigationDestination(
                        workspace: .alerts, tab: .alertsOpen,
                        filters: [
                            "from": "\(Int(bucket.start.timeIntervalSince1970))",
                            "to":   "\(Int(bucket.end.timeIntervalSince1970))"
                        ]
                    ))
                }
            )
            .frame(height: 180)
            histogramLegend
        }
        .v2Panel()
    }

    private var histogramLegend: some View {
        HStack(spacing: 14) {
            legendDot(color: V2Theme.critical, label: String(localized: "overview.legendCritical", defaultValue: "Critical"))
            legendDot(color: V2Theme.high,     label: String(localized: "overview.legendHigh", defaultValue: "High"))
            legendDot(color: V2Theme.medium,   label: String(localized: "overview.legendMedium", defaultValue: "Medium"))
            legendDot(color: V2Theme.low,      label: String(localized: "overview.legendLow", defaultValue: "Low"))
            Spacer()
            Text(String(localized: "overview.histogramHint", defaultValue: "Hover for details · click a bar to open Alerts for that window"))
                .font(V2Theme.meta())
                .foregroundStyle(V2Theme.tertiaryText)
        }
    }

    private func legendDot(color: Color, label: String) -> some View {
        HStack(spacing: 4) {
            RoundedRectangle(cornerRadius: 1.5)
                .fill(color)
                .frame(width: 9, height: 9)
            Text(label).font(V2Theme.meta()).foregroundStyle(V2Theme.mutedText)
        }
    }

    private func rangeChip(_ label: String) -> some View {
        let on = rangeKey == label
        return Button { rangeKey = label } label: {
            Text(label)
                .font(V2Theme.meta())
                .foregroundStyle(on ? V2Theme.primaryText : V2Theme.mutedText)
                .padding(.horizontal, 8).padding(.vertical, 4)
                .background(on ? V2Theme.panelBackground : .clear)
                .overlay(
                    RoundedRectangle(cornerRadius: 4)
                        .stroke(on ? V2Theme.panelBorder : .clear, lineWidth: 1)
                )
                .clipShape(RoundedRectangle(cornerRadius: 4))
                .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityLabel(String(localized: "overview.rangeChipA11y", defaultValue: "Range: \(label)"))
        .accessibilityAddTraits(on ? [.isSelected] : [])
    }

    // MARK: - Forensics & plugins (issue #2)

    private var forensicsCard: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Text(String(localized: "overview.forensicsTitle", defaultValue: "Forensics & plugins")).font(V2Theme.sectionTitle()).foregroundStyle(V2Theme.primaryText)
                Spacer()
                Button { state.switchWorkspace(.forensics) } label: {
                    Text(String(localized: "overview.forensicsOpen", defaultValue: "Open →")).font(V2Theme.meta()).foregroundStyle(V2Theme.dataAccent)
                }
                .buttonStyle(.plain)
            }
            HStack(spacing: 24) {
                forensicsStat("\(forensicsBuiltinCount)", String(localized: "overview.forensicsBuiltinScanners", defaultValue: "Built-in scanners"))
                forensicsStat("\(forensicsInstalledCount)", String(localized: "overview.forensicsInstalledPlugins", defaultValue: "Installed plugins"))
            }
            if let s = forensicsLastScan {
                HStack(spacing: 8) {
                    Image(systemName: "clock.arrow.circlepath").scaledSystem(11).foregroundStyle(V2Theme.mutedText)
                    Text(String(localized: "overview.forensicsLastScan", defaultValue: "Last scan: \(s.name)")).font(V2Theme.body()).foregroundStyle(V2Theme.primaryText).lineLimit(1)
                    Spacer()
                    Text(V2TimeFormat.relative(s.createdAt)).font(V2Theme.meta()).foregroundStyle(V2Theme.tertiaryText)
                }
            } else {
                Text(String(localized: "overview.forensicsNoScans", defaultValue: "No scans yet — run one to inventory this Mac."))
                    .font(V2Theme.body()).foregroundStyle(V2Theme.mutedText)
            }
            HStack(spacing: 8) {
                Button {
                    state.goto(V2NavigationDestination(workspace: .forensics, tab: .forensicsScans))
                } label: {
                    Label(String(localized: "overview.forensicsRunScan", defaultValue: "Run a scan"), systemImage: "play.fill")
                }
                .buttonStyle(.borderedProminent).controlSize(.small)
                // "My plugins" merged into Run a scan (v1.19.3) — one inventory.
            }

            // --- Plugin store + news ---
            Divider().padding(.vertical, 2)
            HStack {
                Text(String(localized: "overview.storeTitle", defaultValue: "Plugin store"))
                    .font(V2Theme.sectionTitle()).foregroundStyle(V2Theme.primaryText)
                Spacer()
                Button {
                    state.goto(V2NavigationDestination(workspace: .forensics, tab: .forensicsCatalog))
                } label: {
                    Text(String(localized: "overview.storeBrowse", defaultValue: "Browse →"))
                        .font(V2Theme.meta()).foregroundStyle(V2Theme.dataAccent)
                }
                .buttonStyle(.plain)
            }
            Text(storeStatusText).font(V2Theme.body()).foregroundStyle(V2Theme.mutedText)
                .fixedSize(horizontal: false, vertical: true)
            ForEach(storeNews) { item in
                HStack(alignment: .top, spacing: 8) {
                    Image(systemName: "sparkles").scaledSystem(11)
                        .foregroundStyle(V2Theme.dataAccent).padding(.top, 2).accessibilityHidden(true)
                    VStack(alignment: .leading, spacing: 1) {
                        HStack(spacing: 6) {
                            // verbatim: never route news text through Text(_:)'s
                            // LocalizedStringKey markdown/auto-link path.
                            Text(verbatim: item.title).font(V2Theme.body()).fontWeight(.medium)
                                .foregroundStyle(V2Theme.primaryText)
                                .lineLimit(1).truncationMode(.tail)
                            if let badge = item.badge {
                                Text(verbatim: badge)
                                    .font(.system(size: 9, weight: .semibold))
                                    .padding(.horizontal, 5).padding(.vertical, 1)
                                    .background(V2Theme.dataAccent.opacity(0.15))
                                    .foregroundStyle(V2Theme.dataAccent)
                                    .clipShape(Capsule())
                            }
                        }
                        Text(verbatim: item.summary).font(V2Theme.meta()).foregroundStyle(V2Theme.mutedText)
                            .lineLimit(2).truncationMode(.tail)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
            }
        }
        .v2Panel()
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    /// One-line plugin-store status. We do NOT auto-fetch the catalog on Overview
    /// (a network call) — the store is browse-on-demand, so this just invites the
    /// user into the signed catalog.
    private var storeStatusText: String {
        String(localized: "overview.storeBrowsePrompt",
               defaultValue: "Browse signed forensic plugins from the catalog. Installs run fully sandboxed.")
    }

    private func forensicsStat(_ value: String, _ label: String) -> some View {
        VStack(alignment: .leading, spacing: 1) {
            Text(value).scaledSystem(22, weight: .semibold).foregroundStyle(V2Theme.primaryText)
            Text(label).font(V2Theme.meta()).foregroundStyle(V2Theme.mutedText)
        }
    }

    private func loadForensicsCard() async {
        // PERF-1: this card shows built-in/installed scanner counts + the newest
        // scan — all of which change only when the plugins dir or the cases dir
        // changes. Gate the per-tick fan-out (manifests + installer.list +
        // listCases-decodes-every-manifest) on those two dirs' mtime so the
        // common 5s refresh tick is free, like the sibling threat-intel tile.
        // The built-in registry is populated lazily; ensure it's bootstrapped
        // (once per process — cheap after the first call) BEFORE we count, so a
        // cold launch doesn't record builtinCount=0 and then lock it in via the
        // mtime gate (registration bumps no directory mtime).
        // Bundled (no-network) store news feed — set once; cheap to recompute.
        if storeNews.isEmpty {
            let news = StoreNews.bundled(appVersion: MacCrabVersion.current)
            await MainActor.run { storeNews = news }
        }
        await BuiltinBootstrapOnce.shared.ensure()
        let installer = PluginInstaller()
        let fm = FileManager.default
        let token = [CaseDirectoryLayout.defaultCasesRoot.path, installer.pluginsRootPath]
            .map { (try? fm.attributesOfItem(atPath: $0))?[.modificationDate] as? Date ?? .distantPast }
            .max() ?? .distantPast
        if let last = lastForensicsCardToken, token <= last { return }   // nothing changed → skip

        let mans = await PluginRegistry.shared.manifests()
        let builtinCount = mans.filter { $0.type == .collector || $0.type == .analyzer }.count
        let builtinIDs = Set(mans.map { $0.id })
        let installed = OperatorVisibilityFilter.filter((try? await installer.list()) ?? [], builtinIDs: builtinIDs)
        var lastScan: CaseManifest? = nil
        let mgr = CaseManager(casesRoot: CaseDirectoryLayout.defaultCasesRoot, dekVault: KeychainDEKVault())
        if let raw = try? await mgr.listCases() {
            lastScan = OperatorVisibilityFilter.filter(raw.sorted { $0.createdAt > $1.createdAt }).first
        }
        await MainActor.run {
            forensicsBuiltinCount = builtinCount
            forensicsInstalledCount = installed.count
            forensicsLastScan = lastScan
            lastForensicsCardToken = token
        }
    }

    private var recentActivityCard: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Text(String(localized: "overview.recentActivityTitle", defaultValue: "Recent activity")).font(V2Theme.sectionTitle()).foregroundStyle(V2Theme.primaryText)
                Spacer()
                Button {
                    state.goto(V2NavigationDestination(
                        workspace: .events, tab: nil
                    ))
                } label: {
                    Text(String(localized: "overview.viewAll", defaultValue: "View all →")).font(V2Theme.meta()).foregroundStyle(V2Theme.dataAccent)
                }
                .buttonStyle(.plain)
            }
            VStack(spacing: 6) {
                ForEach(Array(alerts.prefix(5))) { alert in
                    activityRow(alert: alert)
                }
                if alerts.isEmpty {
                    Text(String(localized: "overview.noRecentAlerts", defaultValue: "No recent alerts."))
                        .font(V2Theme.body())
                        .foregroundStyle(V2Theme.mutedText)
                        .padding(20)
                }
            }
        }
        .v2Panel()
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private func activityRow(alert: V2MockAlert) -> some View {
        Button {
            state.goto(V2NavigationDestination(workspace: .alerts, tab: .alertsOpen, entityId: alert.id))
        } label: {
            HStack(spacing: 10) {
                V2SeverityDot(alert.severity.chipKind)
                VStack(alignment: .leading, spacing: 1) {
                    Text(alert.title)
                        .font(V2Theme.body())
                        .foregroundStyle(V2Theme.primaryText)
                        .lineLimit(1)
                    Text("\(alert.process) · \(alert.category)")
                        .font(V2Theme.meta())
                        .foregroundStyle(V2Theme.mutedText)
                }
                Spacer()
                Text(V2TimeFormat.relative(alert.timestamp))
                    .font(V2Theme.meta())
                    .foregroundStyle(V2Theme.tertiaryText)
                Image(systemName: "chevron.forward")
                    .scaledSystem(9, weight: .semibold)
                    .foregroundStyle(V2Theme.tertiaryText)
            }
            .padding(.horizontal, 10).padding(.vertical, 8)
            .background(V2Theme.panelBackground)
            .clipShape(RoundedRectangle(cornerRadius: V2Theme.smallCornerRadius))
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }

    private var quickActionsCard: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Text(String(localized: "overview.quickActionsTitle", defaultValue: "Quick actions")).font(V2Theme.sectionTitle()).foregroundStyle(V2Theme.primaryText)
                Spacer()
            }
            LazyVGrid(
                columns: [GridItem(.flexible(), spacing: 8), GridItem(.flexible(), spacing: 8)],
                alignment: .leading,
                spacing: 8
            ) {
                quickAction(String(localized: "overview.qaSearchEvents", defaultValue: "Search events"), icon: "magnifyingglass") {
                    state.switchWorkspace(.events)
                }
                quickAction(String(localized: "overview.qaOpenTraceGraph", defaultValue: "Open TraceGraph"), icon: "point.3.connected.trianglepath.dotted") {
                    state.goto(V2NavigationDestination(workspace: .investigation, tab: .investigationTraceGraph))
                }
                quickAction(String(localized: "overview.qaCreateRule", defaultValue: "Create rule"), icon: "plus.app.fill") {
                    state.goto(V2NavigationDestination(workspace: .detection, tab: .detectionRules))
                    state.presentNewRuleTick += 1
                }
                quickAction(String(localized: "overview.qaIntelFeeds", defaultValue: "Intel feeds"), icon: "globe.americas.fill") {
                    state.goto(V2NavigationDestination(workspace: .intelligence, tab: .intelligenceThreatIntel))
                }
                quickAction(String(localized: "overview.qaSystemHealth", defaultValue: "System health"), icon: "waveform.path.ecg") {
                    state.goto(V2NavigationDestination(workspace: .system, tab: .systemHealth))
                }
                quickAction(String(localized: "overview.qaIntegrations", defaultValue: "Integrations"), icon: "powerplug.fill") {
                    state.goto(V2NavigationDestination(workspace: .intelligence, tab: .intelligenceIntegrations))
                }
            }
        }
        .v2Panel()
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private func quickAction(_ label: String, icon: String, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            HStack(spacing: 8) {
                Image(systemName: icon)
                    .scaledSystem(13, weight: .medium)
                    .foregroundStyle(V2Theme.dataAccent)
                    .frame(width: 18, alignment: .center)
                Text(label)
                    .scaledSystem(12, weight: .medium)
                    .foregroundStyle(V2Theme.primaryText)
                    .lineLimit(1)
                    .truncationMode(.tail)
                Spacer(minLength: 0)
            }
            .padding(.horizontal, 10)
            .padding(.vertical, 9)
            .frame(maxWidth: .infinity, minHeight: 36, alignment: .leading)
            .background(V2Theme.panelBackground)
            .overlay(
                RoundedRectangle(cornerRadius: V2Theme.smallCornerRadius)
                    .stroke(V2Theme.panelBorder, lineWidth: 1)
            )
            .clipShape(RoundedRectangle(cornerRadius: V2Theme.smallCornerRadius))
        }
        .buttonStyle(.plain)
    }

    // MARK: - Security factors sheet

    private var securityFactorsSheet: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack(spacing: 12) {
                ZStack {
                    Circle().fill(securityGradeIconColor.opacity(0.18))
                    Text(appState.securityGrade.isEmpty ? "?" : appState.securityGrade)
                        .scaledSystem(22, weight: .bold)
                        .foregroundStyle(securityGradeIconColor)
                }
                .frame(width: 56, height: 56)
                VStack(alignment: .leading, spacing: 2) {
                    Text(String(localized: "overview.sheetSecurityGrade", defaultValue: "Security Grade"))
                        .font(V2Theme.sectionTitle())
                        .foregroundStyle(V2Theme.primaryText)
                    Text(appState.securityScore == 0
                         ? String(localized: "overview.sheetScoringInProgress", defaultValue: "Scoring in progress…")
                         : String(localized: "overview.sheetScoreAcrossChecks", defaultValue: "\(appState.securityScore) / 100 across \(appState.securityFactors.count) checks"))
                        .font(V2Theme.body())
                        .foregroundStyle(V2Theme.mutedText)
                }
                Spacer()
                Button(String(localized: "overview.sheetDone", defaultValue: "Done")) { showingSecurityFactors = false }
                    .keyboardShortcut(.cancelAction)
            }
            .padding(.bottom, 4)

            if appState.securityFactors.isEmpty {
                V2EmptyState(
                    title: String(localized: "overview.emptyFactorsTitle", defaultValue: "No factors yet"),
                    body: String(localized: "overview.emptyFactorsBody", defaultValue: "The security scorer runs every 5 minutes. Wait a moment, then re-open this view."),
                    icon: "hourglass"
                )
                .v2Panel()
            } else {
                ScrollView {
                    VStack(alignment: .leading, spacing: 8) {
                        ForEach(appState.securityFactors.indices, id: \.self) { idx in
                            let f = appState.securityFactors[idx]
                            let isExpanded = expandedFactorName == f.name
                            VStack(alignment: .leading, spacing: 0) {
                                Button {
                                    withAnimation(.easeInOut(duration: 0.15)) {
                                        expandedFactorName = isExpanded ? nil : f.name
                                    }
                                } label: {
                                    HStack(alignment: .top, spacing: 10) {
                                        Image(systemName: factorIcon(f.status))
                                            .foregroundStyle(factorColor(f.status))
                                            .frame(width: 16)
                                        VStack(alignment: .leading, spacing: 2) {
                                            HStack {
                                                Text(f.name)
                                                    .scaledSystem(13, weight: .semibold)
                                                    .foregroundStyle(V2Theme.primaryText)
                                                Spacer()
                                                Text("\(f.score)/\(f.maxScore)")
                                                    .font(V2Theme.mono())
                                                    .foregroundStyle(V2Theme.mutedText)
                                                Image(systemName: "chevron.right")
                                                    .scaledSystem(10)
                                                    .foregroundStyle(V2Theme.tertiaryText)
                                                    .rotationEffect(.degrees(isExpanded ? 90 : 0))
                                                    .accessibilityHidden(true)
                                            }
                                            Text(f.detail)
                                                .font(V2Theme.meta())
                                                .foregroundStyle(V2Theme.mutedText)
                                        }
                                        .contentShape(Rectangle())
                                    }
                                }
                                .buttonStyle(.plain)
                                .help(String(localized: "overview.factorExpandHint", defaultValue: "Click for what this means and how to address it"))

                                if isExpanded {
                                    securityFactorGuideView(SecurityFactorGuide.forFactor(name: f.name, detail: f.detail))
                                        .padding(.top, 10)
                                        .padding(.leading, 26)
                                        .transition(.opacity.combined(with: .move(edge: .top)))
                                }
                            }
                            .padding(10)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .background(V2Theme.panelBackground)
                            .clipShape(RoundedRectangle(cornerRadius: V2Theme.smallCornerRadius))
                        }
                    }
                }
            }
        }
        .padding(20)
        .frame(minWidth: 520, minHeight: 480)
    }

    private func factorIcon(_ status: String) -> String {
        switch status {
        case "pass": return "checkmark.circle.fill"
        case "warn": return "exclamationmark.triangle.fill"
        case "fail": return "xmark.octagon.fill"
        default:     return "questionmark.circle"
        }
    }

    private func factorColor(_ status: String) -> Color {
        switch status {
        case "pass": return V2Theme.healthy
        case "warn": return V2Theme.warning
        case "fail": return V2Theme.high
        default:     return V2Theme.mutedText
        }
    }

    /// Inline "what this means + how to address it" for an expanded factor row,
    /// ending in a Learn-more link to the authoritative Apple documentation.
    @ViewBuilder
    private func securityFactorGuideView(_ guide: SecurityFactorGuide) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            guideRow(String(localized: "overview.factorWhat", defaultValue: "What it is"), guide.what)
            guideRow(String(localized: "overview.factorWhy", defaultValue: "Why it matters"), guide.why)
            if let fix = guide.howToFix {
                guideRow(String(localized: "overview.factorFix", defaultValue: "How to address"), fix)
            }
            if let url = guide.docURL {
                Link(destination: url) {
                    HStack(spacing: 4) {
                        Image(systemName: "arrow.up.right.square").scaledSystem(11)
                        Text(guide.docTitle ?? String(localized: "overview.factorLearnMore", defaultValue: "Learn more"))
                    }
                    .font(V2Theme.meta())
                    .foregroundStyle(V2Theme.dataAccent)
                }
                .buttonStyle(.plain)
                .help(url.absoluteString)
            }
        }
    }

    private func guideRow(_ label: String, _ text: String) -> some View {
        VStack(alignment: .leading, spacing: 1) {
            Text(label.uppercased())
                .font(V2Theme.meta()).fontWeight(.semibold)
                .foregroundStyle(V2Theme.tertiaryText)
            Text(text)
                .font(V2Theme.body()).foregroundStyle(V2Theme.primaryText)
                .fixedSize(horizontal: false, vertical: true)
        }
    }
}

// MARK: - Alert volume histogram
//
// Stacked bar chart of alert counts per time bucket. Each bar:
//   bottom: low (blue-grey)
//   middle: medium (amber)
//   then:   high (orange)
//   top:    critical (red)
//
// Hover a bar → popover with the bucket time range, total count,
// and per-severity breakdown. Click → drills into Alerts filtered
// to that window. No more abstract "posture line" — the chart now
// answers "when did alerts happen and how bad?" directly.

// Alias the histogram's bucket type to the public V2OverviewBucket
// returned by V2DataProvider.alertHistogram, so the chart renders
// real data without an explicit conversion step.
fileprivate typealias V2AlertBucket = V2OverviewBucket

fileprivate struct V2AlertHistogram: View {
    let rangeKey: String
    let buckets: [V2AlertBucket]
    let onBucketTap: (V2AlertBucket) -> Void

    @State private var hoverBucketId: UUID?

    private let topInset: CGFloat = 12
    private let bottomInset: CGFloat = 28
    private let yAxisWidth: CGFloat = 40
    private let barGap: CGFloat = 2

    private var maxCount: Int {
        max(buckets.map(\.total).max() ?? 1, 1)
    }

    var body: some View {
        GeometryReader { geo in
            let chartFrame = CGRect(
                x: yAxisWidth,
                y: topInset,
                width: max(geo.size.width - yAxisWidth, 1),
                height: max(geo.size.height - topInset - bottomInset, 1)
            )
            ZStack(alignment: .topLeading) {
                yAxis(in: geo.size, chartFrame: chartFrame)
                gridLines(chartFrame: chartFrame)
                bars(chartFrame: chartFrame)
                xAxis(in: geo.size, chartFrame: chartFrame)
                if let id = hoverBucketId,
                   let bucket = buckets.first(where: { $0.id == id }) {
                    hoverPopover(for: bucket, chartFrame: chartFrame)
                        .allowsHitTesting(false)
                }
            }
        }
    }

    // MARK: - Y axis + grid

    private func yAxis(in canvas: CGSize, chartFrame: CGRect) -> some View {
        let steps = niceTicks(maxValue: maxCount)
        return ZStack(alignment: .topLeading) {
            ForEach(steps.indices, id: \.self) { i in
                let v = steps[i]
                let y = chartFrame.minY + chartFrame.height * (1 - CGFloat(v) / CGFloat(maxCount))
                Text("\(v)")
                    .scaledSystem(10, weight: .medium)
                    .foregroundStyle(V2Theme.tertiaryText)
                    .monospacedDigit()
                    .frame(width: yAxisWidth - 8, alignment: .trailing)
                    .position(x: (yAxisWidth - 4) / 2, y: y)
            }
        }
    }

    private func gridLines(chartFrame: CGRect) -> some View {
        let steps = niceTicks(maxValue: maxCount)
        return ZStack(alignment: .topLeading) {
            ForEach(steps.indices, id: \.self) { i in
                let v = steps[i]
                let y = chartFrame.minY + chartFrame.height * (1 - CGFloat(v) / CGFloat(maxCount))
                Path { p in
                    p.move(to: .init(x: chartFrame.minX, y: y))
                    p.addLine(to: .init(x: chartFrame.maxX, y: y))
                }
                .stroke(V2Theme.panelBorder.opacity(v == 0 ? 0.6 : 0.3),
                        style: v == 0 ? StrokeStyle(lineWidth: 0.5)
                                      : StrokeStyle(lineWidth: 0.5, dash: [3, 4]))
            }
        }
    }

    /// Pretty tick spacing — 0, mid, max. Up to 5 lines for tall
    /// counts.
    private func niceTicks(maxValue: Int) -> [Int] {
        guard maxValue > 0 else { return [0] }
        if maxValue <= 4 { return Array(0...maxValue) }
        if maxValue <= 10 { return [0, maxValue / 2, maxValue] }
        let step = roundUpNice(maxValue / 4)
        var t = [0]
        var v = step
        while v < maxValue { t.append(v); v += step }
        t.append(maxValue)
        return t
    }
    private func roundUpNice(_ x: Int) -> Int {
        if x <= 1 { return 1 }
        if x <= 5 { return 5 }
        if x <= 10 { return 10 }
        if x <= 50 { return ((x + 9) / 10) * 10 }
        return ((x + 49) / 50) * 50
    }

    // MARK: - Bars

    private func bars(chartFrame: CGRect) -> some View {
        let n = max(buckets.count, 1)
        let totalGap = barGap * CGFloat(n - 1)
        let barWidth = max((chartFrame.width - totalGap) / CGFloat(n), 4)
        return ZStack(alignment: .topLeading) {
            ForEach(buckets.indices, id: \.self) { i in
                let bucket = buckets[i]
                let x = chartFrame.minX + (barWidth + barGap) * CGFloat(i)
                bar(for: bucket, x: x, width: barWidth, chartFrame: chartFrame)
            }
        }
    }

    private func bar(for bucket: V2AlertBucket, x: CGFloat, width: CGFloat, chartFrame: CGRect) -> some View {
        let total = bucket.total
        let isHover = hoverBucketId == bucket.id
        // Heights for each severity stack, in the order they're drawn
        // (bottom-up: low, medium, high, critical).
        let stack: [(Int, Color)] = [
            (bucket.low,      V2Theme.low),
            (bucket.medium,   V2Theme.medium),
            (bucket.high,     V2Theme.high),
            (bucket.critical, V2Theme.critical),
        ]
        return Button {
            onBucketTap(bucket)
        } label: {
            ZStack(alignment: .bottom) {
                // Empty-bucket placeholder so 0-count bars still
                // expose a hover target.
                if total == 0 {
                    RoundedRectangle(cornerRadius: 2)
                        .fill(V2Theme.panelBorder)
                        .frame(width: width, height: 2)
                }
                VStack(spacing: 0) {
                    ForEach(stack.indices.reversed(), id: \.self) { i in
                        let (count, color) = stack[i]
                        if count > 0 {
                            let h = chartFrame.height * CGFloat(count) / CGFloat(maxCount)
                            Rectangle()
                                .fill(isHover ? color : color.opacity(0.85))
                                .frame(width: width, height: h)
                        }
                    }
                }
                .clipShape(RoundedRectangle(cornerRadius: 3))
            }
            .frame(width: width, height: chartFrame.height, alignment: .bottom)
            .overlay(alignment: .top) {
                // Hover halo
                if isHover {
                    Rectangle()
                        .stroke(V2Theme.primaryText.opacity(0.6), lineWidth: 1)
                        .frame(width: width, height: chartFrame.height)
                        .padding(.horizontal, -2)
                }
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .onHover { hoverBucketId = $0 ? bucket.id : (hoverBucketId == bucket.id ? nil : hoverBucketId) }
        .position(x: x + width / 2, y: chartFrame.midY)
    }

    // MARK: - X axis

    private func xAxis(in canvas: CGSize, chartFrame: CGRect) -> some View {
        let formatter = DateFormatter()
        switch rangeKey {
        case "1h", "6h":  formatter.dateFormat = "HH:mm"
        case "24h":       formatter.dateFormat = "HH:mm"
        case "7d":        formatter.dateFormat = "MMM d"
        default:          formatter.dateFormat = "HH:mm"
        }
        // Show 5 evenly-spaced labels regardless of bucket count.
        let labelCount = 5
        let now = Date()
        return ZStack(alignment: .topLeading) {
            ForEach(0..<labelCount, id: \.self) { i in
                let frac = CGFloat(i) / CGFloat(max(labelCount - 1, 1))
                let x = chartFrame.minX + chartFrame.width * frac
                let firstStart = buckets.first?.start ?? now
                let lastEnd = buckets.last?.end ?? now
                let span = lastEnd.timeIntervalSince(firstStart)
                let t = firstStart.addingTimeInterval(span * Double(frac))
                let primary = formatter.string(from: t)
                let secondary = i == labelCount - 1 ? String(localized: "overview.histogramNow", defaultValue: "now") : V2AlertHistogram.relative(seconds: -t.timeIntervalSinceNow)
                VStack(spacing: 0) {
                    Text(primary)
                        .scaledSystem(10, weight: .medium)
                        .foregroundStyle(V2Theme.mutedText)
                        .monospacedDigit()
                    Text(secondary)
                        .scaledSystem(8)
                        .foregroundStyle(V2Theme.tertiaryText)
                }
                .frame(width: 60)
                .position(x: x, y: chartFrame.maxY + bottomInset / 2 + 2)
            }
        }
    }

    private static func relative(seconds s: TimeInterval) -> String {
        if s < 60         { return "−\(Int(s))s" }
        if s < 3_600      { return "−\(Int(s / 60))m" }
        if s < 86_400     { return "−\(Int(s / 3_600))h" }
        return "−\(Int(s / 86_400))d"
    }

    // MARK: - Hover popover

    private func hoverPopover(for bucket: V2AlertBucket, chartFrame: CGRect) -> some View {
        let i = buckets.firstIndex { $0.id == bucket.id } ?? 0
        let n = max(buckets.count, 1)
        let totalGap = barGap * CGFloat(n - 1)
        let barWidth = max((chartFrame.width - totalGap) / CGFloat(n), 4)
        let barCenterX = chartFrame.minX + (barWidth + barGap) * CGFloat(i) + barWidth / 2
        let popoverWidth: CGFloat = 220
        let halfPopover = popoverWidth / 2
        let popoverX = min(max(barCenterX, chartFrame.minX + halfPopover + 4),
                           chartFrame.maxX - halfPopover - 4)
        let dateFmt = DateFormatter()
        dateFmt.dateFormat = "HH:mm"
        let dayFmt = DateFormatter()
        dayFmt.dateFormat = "MMM d"
        let startStr = dateFmt.string(from: bucket.start)
        let endStr = dateFmt.string(from: bucket.end)
        let dayStr = dayFmt.string(from: bucket.start)
        return VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 6) {
                Image(systemName: "clock")
                    .scaledSystem(9)
                    .foregroundStyle(V2Theme.mutedText)
                Text("\(dayStr) · \(startStr) – \(endStr)")
                    .scaledSystem(11, weight: .semibold)
                    .foregroundStyle(V2Theme.primaryText)
                    .monospacedDigit()
            }
            Divider().background(V2Theme.panelBorder)
            HStack {
                Text(String(localized: "overview.popoverTotal", defaultValue: "Total"))
                    .scaledSystem(10, weight: .medium)
                    .foregroundStyle(V2Theme.mutedText)
                Spacer()
                Text("\(bucket.total) \(bucket.total == 1 ? String(localized: "overview.popoverAlertSingular", defaultValue: "alert") : String(localized: "overview.popoverAlertPlural", defaultValue: "alerts"))")
                    .scaledSystem(11, weight: .semibold)
                    .foregroundStyle(V2Theme.primaryText)
                    .monospacedDigit()
            }
            severityRow(String(localized: "overview.popoverCritical", defaultValue: "Critical"), count: bucket.critical, color: V2Theme.critical)
            severityRow(String(localized: "overview.popoverHigh", defaultValue: "High"),     count: bucket.high,     color: V2Theme.high)
            severityRow(String(localized: "overview.popoverMedium", defaultValue: "Medium"),   count: bucket.medium,   color: V2Theme.medium)
            severityRow(String(localized: "overview.popoverLow", defaultValue: "Low"),      count: bucket.low,      color: V2Theme.low)
            Text(String(localized: "overview.popoverClickHint", defaultValue: "Click bar to open these alerts"))
                .scaledSystem(9)
                .foregroundStyle(V2Theme.tertiaryText)
        }
        .padding(.horizontal, 12).padding(.vertical, 10)
        .frame(width: popoverWidth, alignment: .leading)
        .background(V2Theme.inspectorBackground)
        .overlay(
            RoundedRectangle(cornerRadius: 8)
                .stroke(V2Theme.panelBorder, lineWidth: 1)
        )
        .clipShape(RoundedRectangle(cornerRadius: 8))
        .shadow(color: Color.black.opacity(0.45), radius: 10, x: 0, y: 4)
        .position(x: popoverX, y: chartFrame.minY - 4)
    }

    private func severityRow(_ label: String, count: Int, color: Color) -> some View {
        HStack(spacing: 6) {
            RoundedRectangle(cornerRadius: 1.5)
                .fill(color)
                .frame(width: 8, height: 8)
            Text(label)
                .scaledSystem(10, weight: .medium)
                .foregroundStyle(count > 0 ? V2Theme.neutral : V2Theme.tertiaryText)
            Spacer()
            Text("\(count)")
                .scaledSystem(10, weight: .medium)
                .foregroundStyle(count > 0 ? V2Theme.primaryText : V2Theme.tertiaryText)
                .monospacedDigit()
        }
    }

}

