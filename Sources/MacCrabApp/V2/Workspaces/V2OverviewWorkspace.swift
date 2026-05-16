// V2OverviewWorkspace.swift
// Spec §7.1 — single-screen operational summary. No tabs.

import SwiftUI

struct V2OverviewWorkspace: View {

    @ObservedObject var state: V2DashboardState
    @ObservedObject var appState: AppState
    @State private var alerts: [V2MockAlert] = []
    @State private var campaigns: [V2MockCampaign] = []
    @State private var kpis: V2OverviewKPIs = .zero
    @State private var histogramBuckets: [V2OverviewBucket] = []
    @State private var rangeKey: String = "6h"
    @State private var showingSecurityFactors: Bool = false

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
                protectionBanner
                kpiRow
                postureTimelineCard
                HStack(alignment: .top, spacing: 12) {
                    recentActivityCard
                    quickActionsCard
                }
            }
            .padding(16)
        }
        .sheet(isPresented: $showingSecurityFactors) {
            securityFactorsSheet
        }
        .task(id: "\(state.provider.mode):\(state.refreshTick):\(rangeKey)") {
            let a = await state.provider.alerts(limit: 50)
            let c = await state.provider.campaigns(limit: 20)
            let k = await state.provider.kpis()
            let buckets = await state.provider.alertHistogram(rangeKey: rangeKey)
            await MainActor.run {
                self.alerts = a
                self.campaigns = c
                self.kpis = k
                self.histogramBuckets = buckets
            }
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
        if state.provider.mode == .mock { return .inactive }
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
            case .active:   return "Protected — system is secure"
            case .degraded: return "Protection degraded — review System Health"
            case .inactive: return "Protection inactive — daemon not detected"
            }
        }()
        let body: String = {
            switch s {
            case .active:
                let collectors = appState.heartbeat?.collectorHealth?.count ?? 0
                return collectors == 0
                    ? "Live data flowing · collectors active"
                    : "Live data flowing · \(collectors) collectors active"
            case .degraded:
                return "Live data is stale or score is low — open System health for details"
            case .inactive:
                return "Start the System Extension or run `swift run maccrabd` to begin protection"
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
                        .font(.system(size: 18, weight: .bold))
                }
                VStack(alignment: .leading, spacing: 1) {
                    Text(title)
                        .font(.system(size: 14, weight: .semibold))
                        .foregroundStyle(V2Theme.primaryText)
                    Text(body)
                        .font(V2Theme.meta())
                        .foregroundStyle(V2Theme.primaryText.opacity(0.7))
                }
                Spacer()
                Image(systemName: "chevron.forward")
                    .font(.system(size: 11, weight: .semibold))
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

    private var kpiRow: some View {
        HStack(alignment: .top, spacing: 8) {
            // Each card stretches to match the tallest one so the row
            // bottoms line up. Without this, cards with footers/visuals
            // were taller than ones without — the misalignment the
            // user flagged.
            Group {
            V2KpiCard(
                title: "Security Grade",
                value: appState.securityGrade.isEmpty ? "—" : appState.securityGrade,
                trend: appState.securityScore == 0 ? "scoring…" : "\(appState.securityScore) / 100",
                trendKind: securityGradeTrendKind,
                icon: "checkmark.seal.fill",
                iconColor: securityGradeIconColor,
                footer: appState.securityFactors.isEmpty
                    ? "Live system posture (SIP, FileVault, firewall, etc.)"
                    : "\(appState.securityFactors.filter { $0.status == "pass" }.count) of \(appState.securityFactors.count) checks pass",
                action: V2KpiAction("View factors") {
                    showingSecurityFactors = true
                }
            )
            V2KpiCard(
                title: "Open Alerts",
                value: "\(kpis.openAlerts24h)",
                trend: openAlertsTrendLabel,
                trendKind: openAlertsTrendKind,
                icon: "bell.fill",
                iconColor: V2Theme.high,
                action: V2KpiAction("View Alerts") {
                    state.goto(V2NavigationDestination(workspace: .alerts, tab: .alertsOpen))
                },
                visual: kpis.eventsLast8Buckets.isEmpty
                    ? nil
                    : .sparkline(values: kpis.eventsLast8Buckets, color: V2Theme.high)
            )
            V2KpiCard(
                title: "Active Campaigns",
                value: "\(kpis.activeCampaigns)",
                trend: campaignTrendLabel,
                trendKind: kpis.activeCampaignsCritical > 0 ? .critical
                    : kpis.activeCampaignsHigh > 0 ? .high : .info,
                icon: "flame.fill",
                iconColor: kpis.activeCampaignsCritical > 0 ? V2Theme.critical : V2Theme.high,
                action: V2KpiAction("View Campaigns") {
                    state.goto(V2NavigationDestination(workspace: .alerts, tab: .alertsCampaigns))
                }
            )
            V2KpiCard(
                title: "Event Rate",
                value: formatRate(kpis.eventsPerSecond),
                trend: "/sec · last 1m",
                trendKind: .info,
                icon: "waveform.path",
                iconColor: V2Theme.dataAccent,
                action: V2KpiAction("View Events") {
                    state.goto(V2NavigationDestination(
                        workspace: .events, tab: nil
                    ))
                },
                visual: kpis.eventsLast8Buckets.isEmpty
                    ? nil
                    : .bars(values: kpis.eventsLast8Buckets, color: V2Theme.dataAccent)
            )
            V2KpiCard(
                title: "AI Guard",
                value: "—",
                trend: "via daemon",
                trendKind: .neutral,
                icon: "brain.head.profile",
                iconColor: V2Theme.aiAccent,
                action: V2KpiAction("View AI Guard") {
                    state.goto(V2NavigationDestination(
                        workspace: .detection, tab: .detectionAIGuard
                    ))
                }
            )
            V2KpiCard(
                title: "Threat Intel",
                value: "—",
                trend: "via daemon",
                trendKind: .neutral,
                icon: "globe.americas.fill",
                iconColor: V2Theme.dataAccent,
                action: V2KpiAction("View Intelligence") {
                    state.goto(V2NavigationDestination(
                        workspace: .intelligence, tab: .intelligenceThreatIntel
                    ))
                }
            )
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
        }
        .frame(height: 124)
    }

    private var openAlertsTrendLabel: String {
        let d = kpis.openAlertsLast24hDelta
        if d == 0 { return "no change vs prior 24h" }
        return d > 0 ? "+\(d) vs prior 24h" : "\(d) vs prior 24h"
    }
    private var openAlertsTrendKind: V2ChipKind {
        kpis.openAlertsLast24hDelta > 0 ? .warning : .healthy
    }
    private var campaignTrendLabel: String {
        if kpis.activeCampaigns == 0 { return "none active" }
        var parts: [String] = []
        if kpis.activeCampaignsCritical > 0 { parts.append("\(kpis.activeCampaignsCritical) critical") }
        if kpis.activeCampaignsHigh > 0     { parts.append("\(kpis.activeCampaignsHigh) high") }
        if kpis.activeCampaignsMedium > 0   { parts.append("\(kpis.activeCampaignsMedium) medium") }
        return parts.isEmpty ? "active" : parts.joined(separator: " · ")
    }
    private func formatRate(_ rate: Double) -> String {
        if rate >= 1000 { return String(format: "%.1fK", rate / 1000) }
        if rate >= 10   { return String(format: "%.0f", rate) }
        return String(format: "%.1f", rate)
    }

    private var postureTimelineCard: some View {
        let buckets = histogramBuckets
        let total = buckets.reduce(0) { $0 + $1.total }
        return VStack(alignment: .leading, spacing: 10) {
            HStack {
                Text("Alert volume — last \(rangeKey)")
                    .font(V2Theme.sectionTitle()).foregroundStyle(V2Theme.primaryText)
                Text("· \(total) total")
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
            legendDot(color: V2Theme.critical, label: "Critical")
            legendDot(color: V2Theme.high,     label: "High")
            legendDot(color: V2Theme.medium,   label: "Medium")
            legendDot(color: V2Theme.low,      label: "Low")
            Spacer()
            Text("Hover for details · click a bar to open Alerts for that window")
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
        .accessibilityLabel("Range: \(label)")
        .accessibilityAddTraits(on ? [.isSelected] : [])
    }

    private var recentActivityCard: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Text("Recent activity").font(V2Theme.sectionTitle()).foregroundStyle(V2Theme.primaryText)
                Spacer()
                Button {
                    state.goto(V2NavigationDestination(
                        workspace: .events, tab: nil
                    ))
                } label: {
                    Text("View all →").font(V2Theme.meta()).foregroundStyle(V2Theme.dataAccent)
                }
                .buttonStyle(.plain)
            }
            VStack(spacing: 6) {
                ForEach(Array(alerts.prefix(5))) { alert in
                    activityRow(alert: alert)
                }
                if alerts.isEmpty {
                    Text("No recent alerts.")
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
                    .font(.system(size: 9, weight: .semibold))
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
                Text("Quick actions").font(V2Theme.sectionTitle()).foregroundStyle(V2Theme.primaryText)
                Spacer()
            }
            LazyVGrid(
                columns: [GridItem(.flexible(), spacing: 8), GridItem(.flexible(), spacing: 8)],
                alignment: .leading,
                spacing: 8
            ) {
                quickAction("Search events", icon: "magnifyingglass") {
                    state.switchWorkspace(.events)
                }
                quickAction("Open TraceGraph", icon: "point.3.connected.trianglepath.dotted") {
                    state.goto(V2NavigationDestination(workspace: .investigation, tab: .investigationTraceGraph))
                }
                quickAction("Create rule", icon: "plus.app.fill") {
                    state.goto(V2NavigationDestination(workspace: .detection, tab: .detectionRules))
                    state.presentNewRuleTick += 1
                }
                quickAction("Intel feeds", icon: "globe.americas.fill") {
                    state.goto(V2NavigationDestination(workspace: .intelligence, tab: .intelligenceThreatIntel))
                }
                quickAction("System health", icon: "waveform.path.ecg") {
                    state.goto(V2NavigationDestination(workspace: .system, tab: .systemHealth))
                }
                quickAction("Integrations", icon: "powerplug.fill") {
                    state.goto(V2NavigationDestination(workspace: .intelligence, tab: .intelligenceIntegrations))
                }
            }
        }
        .v2Panel()
        .frame(width: 320)
    }

    private func quickAction(_ label: String, icon: String, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            HStack(spacing: 8) {
                Image(systemName: icon)
                    .font(.system(size: 13, weight: .medium))
                    .foregroundStyle(V2Theme.dataAccent)
                    .frame(width: 18, alignment: .center)
                Text(label)
                    .font(.system(size: 12, weight: .medium))
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
                        .font(.system(size: 22, weight: .bold))
                        .foregroundStyle(securityGradeIconColor)
                }
                .frame(width: 56, height: 56)
                VStack(alignment: .leading, spacing: 2) {
                    Text("Security Grade")
                        .font(V2Theme.sectionTitle())
                        .foregroundStyle(V2Theme.primaryText)
                    Text(appState.securityScore == 0
                         ? "Scoring in progress…"
                         : "\(appState.securityScore) / 100 across \(appState.securityFactors.count) checks")
                        .font(V2Theme.body())
                        .foregroundStyle(V2Theme.mutedText)
                }
                Spacer()
                Button("Done") { showingSecurityFactors = false }
                    .keyboardShortcut(.cancelAction)
            }
            .padding(.bottom, 4)

            if appState.securityFactors.isEmpty {
                V2EmptyState(
                    title: "No factors yet",
                    body: "The security scorer runs every 5 minutes. Wait a moment, then re-open this view.",
                    icon: "hourglass"
                )
                .v2Panel()
            } else {
                ScrollView {
                    VStack(alignment: .leading, spacing: 8) {
                        ForEach(appState.securityFactors.indices, id: \.self) { idx in
                            let f = appState.securityFactors[idx]
                            HStack(alignment: .top, spacing: 10) {
                                Image(systemName: factorIcon(f.status))
                                    .foregroundStyle(factorColor(f.status))
                                    .frame(width: 16)
                                VStack(alignment: .leading, spacing: 2) {
                                    HStack {
                                        Text(f.name)
                                            .font(.system(size: 13, weight: .semibold))
                                            .foregroundStyle(V2Theme.primaryText)
                                        Spacer()
                                        Text("\(f.score)/\(f.maxScore)")
                                            .font(V2Theme.mono())
                                            .foregroundStyle(V2Theme.mutedText)
                                    }
                                    Text(f.detail)
                                        .font(V2Theme.meta())
                                        .foregroundStyle(V2Theme.mutedText)
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
                    .font(.system(size: 10, weight: .medium))
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
                let secondary = i == labelCount - 1 ? "now" : V2AlertHistogram.relative(seconds: -t.timeIntervalSinceNow)
                VStack(spacing: 0) {
                    Text(primary)
                        .font(.system(size: 10, weight: .medium))
                        .foregroundStyle(V2Theme.mutedText)
                        .monospacedDigit()
                    Text(secondary)
                        .font(.system(size: 8))
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
                    .font(.system(size: 9))
                    .foregroundStyle(V2Theme.mutedText)
                Text("\(dayStr) · \(startStr) – \(endStr)")
                    .font(.system(size: 11, weight: .semibold))
                    .foregroundStyle(V2Theme.primaryText)
                    .monospacedDigit()
            }
            Divider().background(V2Theme.panelBorder)
            HStack {
                Text("Total")
                    .font(.system(size: 10, weight: .medium))
                    .foregroundStyle(V2Theme.mutedText)
                Spacer()
                Text("\(bucket.total) \(bucket.total == 1 ? "alert" : "alerts")")
                    .font(.system(size: 11, weight: .semibold))
                    .foregroundStyle(V2Theme.primaryText)
                    .monospacedDigit()
            }
            severityRow("Critical", count: bucket.critical, color: V2Theme.critical)
            severityRow("High",     count: bucket.high,     color: V2Theme.high)
            severityRow("Medium",   count: bucket.medium,   color: V2Theme.medium)
            severityRow("Low",      count: bucket.low,      color: V2Theme.low)
            Text("Click bar to open these alerts")
                .font(.system(size: 9))
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
                .font(.system(size: 10, weight: .medium))
                .foregroundStyle(count > 0 ? V2Theme.neutral : V2Theme.tertiaryText)
            Spacer()
            Text("\(count)")
                .font(.system(size: 10, weight: .medium))
                .foregroundStyle(count > 0 ? V2Theme.primaryText : V2Theme.tertiaryText)
                .monospacedDigit()
        }
    }

    // MARK: - Bucket data

    static func buckets(rangeKey: String) -> [V2AlertBucket] {
        V2MockHistogramFactory.synthBuckets(rangeKey: rangeKey)
    }

    static func synth_DEPRECATED(rangeKey: String) -> [V2AlertBucket] {
        let now = Date()
        let (totalSpan, bucketSpan): (TimeInterval, TimeInterval) = {
            switch rangeKey {
            case "1h":  return (3_600,    300)        // 12 buckets of 5 min
            case "6h":  return (21_600,   1_800)      // 12 buckets of 30 min
            case "24h": return (86_400,   7_200)      // 12 buckets of 2 h
            case "7d":  return (604_800,  43_200)     // 14 buckets of 12 h
            default:    return (21_600,   1_800)
            }
        }()
        let count = Int(totalSpan / bucketSpan)
        return (0..<count).map { i in
            let end = now.addingTimeInterval(-bucketSpan * Double(count - i - 1))
            let start = end.addingTimeInterval(-bucketSpan)
            return synth(rangeKey: rangeKey, index: i, count: count, start: start, end: end)
        }
    }

    /// Mock data with realistic distribution — concentrated bursts
    /// rather than uniform noise, so the chart actually communicates
    /// activity peaks.
    private static func synth(rangeKey: String, index i: Int, count n: Int,
                              start: Date, end: Date) -> V2AlertBucket {
        let frac = Double(i) / Double(max(n - 1, 1))
        // Base hum
        var lo = 0, med = 0, hi = 0, crit = 0
        let hum = Int(2 * (sin(Double(i) / 1.5) + 1)) // 0–4
        lo += hum
        // Range-specific event clusters
        switch rangeKey {
        case "1h":
            if i == 7 || i == 8 { hi += 2 }
            if i == 8 { crit += 1 }
        case "6h":
            if i == 7 { crit += 1; hi += 1 }
            if i == 8 { crit += 1; hi += 2; med += 1 }
            if i == 9 { hi += 1 }
            if i == 10 { med += 2 }
        case "24h":
            if i == 2 { hi += 1 }
            if i == 7 { crit += 1; hi += 1 }
            if i == 8 { crit += 2; hi += 3 }
            if i == 9 { hi += 1; med += 1 }
            if i == 10 { med += 1 }
            if i == 11 { lo += 1 }
        case "7d":
            if i == 1 { med += 2 }
            if i == 4 { hi += 1 }
            if i == 7 { hi += 2; med += 1 }
            if i == 8 { crit += 1; hi += 2 }
            if i == 9 { crit += 2; hi += 1 }
            if i == 12 { lo += 3 }
        default: break
        }
        // Trim bursts off random unrelated buckets to avoid noise
        if frac < 0.4 && (crit + hi) == 0 { lo = max(0, lo - 1) }
        return V2AlertBucket(start: start, end: end,
                             critical: crit, high: hi, medium: med, low: lo)
    }
}

