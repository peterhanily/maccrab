// V2PreventionWorkspace.swift
// Top-level Prevention workspace — DNS sinkhole, network blocker,
// persistence guard, response actions.
//
// Live wiring:
//   - Recent action log: alerts where actionsTaken is non-empty,
//     fetched via the existing alerts() provider call.
//   - Configure response actions: opens the Settings window's
//     "Response Actions" tab where the per-rule action config lives.

import SwiftUI

struct V2PreventionWorkspace: View {
    @ObservedObject var state: V2DashboardState
    @State private var preventionAlerts: [V2MockAlert] = []
    @State private var heartbeat: V2HeartbeatSnapshot?

    init(state: V2DashboardState) { self.state = state }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                preventionStatusStrip
                summaryRow
                configureCard
                recentActionsCard
            }
            .padding(16)
        }
        .task(id: "\(state.provider.mode):\(state.refreshTick)") {
            // Pull a wider alert window so the prevention log isn't
            // empty just because few alerts fired in the last hour.
            let recent = await state.provider.alerts(limit: 200)
            let h = await state.provider.heartbeat()
            await MainActor.run {
                self.preventionAlerts = recent.filter { !$0.actionsTaken.isEmpty }
                self.heartbeat = h
            }
        }
    }

    /// UX-3: live status of the three prevention modules from the daemon
    /// heartbeat. Shows "unavailable" when there's no recent heartbeat (or an
    /// older daemon that doesn't emit the prevention block) rather than a
    /// false reading.
    private var preventionStatusStrip: some View {
        HStack(spacing: 8) {
            if let p = heartbeat?.prevention {
                // Each module/state gets its OWN fully-localized format string so
                // a translator owns the whole phrase (word order, punctuation) —
                // not a shared "%@: on (%lld)" with an injected pre-localized noun.
                preventionChip(
                    on: String(localized: "prevention.chip.sinkhole.on", defaultValue: "DNS Sinkhole: on (\(p.sinkhole.count))"),
                    off: String(localized: "prevention.chip.sinkhole.off", defaultValue: "DNS Sinkhole: off"),
                    enabled: p.sinkhole.enabled)
                preventionChip(
                    on: String(localized: "prevention.chip.networkBlocker.on", defaultValue: "Network Blocker: on (\(p.networkBlocker.count))"),
                    off: String(localized: "prevention.chip.networkBlocker.off", defaultValue: "Network Blocker: off"),
                    enabled: p.networkBlocker.enabled)
                preventionChip(
                    on: String(localized: "prevention.chip.persistenceGuard.on", defaultValue: "Persistence Guard: on (\(p.persistenceGuard.count))"),
                    off: String(localized: "prevention.chip.persistenceGuard.off", defaultValue: "Persistence Guard: off"),
                    enabled: p.persistenceGuard.enabled)
            } else {
                V2StatusChip(String(localized: "prevention.statusUnavailable", defaultValue: "Status unavailable — no recent daemon heartbeat"),
                             kind: .neutral, icon: "questionmark.circle")
            }
            Spacer()
        }
    }

    @ViewBuilder
    private func preventionChip(on: String, off: String, enabled: Bool) -> some View {
        if enabled {
            V2StatusChip(on, kind: .healthy, icon: "checkmark.shield.fill")
        } else {
            V2StatusChip(off, kind: .neutral, icon: "shield.slash")
        }
    }

    private var summaryRow: some View {
        let last24h = preventionAlerts.filter {
            $0.timestamp.timeIntervalSinceNow > -86_400
        }
        let killCount = last24h.filter { a in
            a.actionsTaken.contains(where: { $0.lowercased().contains("kill") })
        }.count
        let blockCount = last24h.filter { a in
            a.actionsTaken.contains(where: { $0.lowercased().contains("block")
                || $0.lowercased().contains("sinkhole") })
        }.count
        let quarantineCount = last24h.filter { a in
            a.actionsTaken.contains(where: { $0.lowercased().contains("quarantine") })
        }.count
        return HStack(spacing: 12) {
            metricCard(title: String(localized: "prevention.metricActions24h", defaultValue: "Actions (24h)"), value: "\(last24h.count)",
                       trend: last24h.isEmpty ? String(localized: "prevention.trendNoTriggers", defaultValue: "no triggers") : String(localized: "prevention.trendReviewLog", defaultValue: "review log"),
                       trendKind: last24h.isEmpty ? .healthy : .info,
                       icon: "bolt.shield", iconColor: V2Theme.dataAccent)
            metricCard(title: String(localized: "prevention.metricProcessKill", defaultValue: "Process kill"), value: "\(killCount)",
                       trend: killCount == 0 ? String(localized: "prevention.trendNone", defaultValue: "none") : String(localized: "prevention.trend24h", defaultValue: "24h"),
                       trendKind: killCount == 0 ? .healthy : .warning,
                       icon: "xmark.octagon", iconColor: killCount == 0 ? V2Theme.healthy : V2Theme.high)
            metricCard(title: String(localized: "prevention.metricBlockSinkhole", defaultValue: "Block / sinkhole"), value: "\(blockCount)",
                       trend: blockCount == 0 ? String(localized: "prevention.trendNone", defaultValue: "none") : String(localized: "prevention.trend24h", defaultValue: "24h"),
                       trendKind: blockCount == 0 ? .healthy : .info,
                       icon: "network.slash", iconColor: V2Theme.dataAccent)
            metricCard(title: String(localized: "prevention.metricQuarantine", defaultValue: "Quarantine"), value: "\(quarantineCount)",
                       trend: quarantineCount == 0 ? String(localized: "prevention.trendNone", defaultValue: "none") : String(localized: "prevention.trend24h", defaultValue: "24h"),
                       trendKind: quarantineCount == 0 ? .healthy : .warning,
                       icon: "tray.full", iconColor: V2Theme.dataAccent)
        }
    }

    private var configureCard: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: "gearshape.fill")
                .foregroundStyle(V2Theme.dataAccent)
                .scaledSystem(14)
                .padding(.top, 2)
            VStack(alignment: .leading, spacing: 6) {
                Text(String(localized: "prevention.configureTitle", defaultValue: "Configure prevention")).font(V2Theme.sectionTitle()).foregroundStyle(V2Theme.primaryText)
                Text(String(localized: "prevention.configureBody", defaultValue: "Per-rule response actions (kill, block, sinkhole, quarantine, deny-allowlist) live in `actions.json` under the data dir. Edit them from Settings → Response Actions; the daemon picks up changes on the next SIGHUP (or restart)."))
                    .font(V2Theme.body()).foregroundStyle(V2Theme.mutedText)
                Text(String(localized: "prevention.ruleDriven", defaultValue: "Response actions are rule-driven: each one fires automatically when its detection rule matches. They are not triggered manually from this screen."))
                    .font(V2Theme.body()).foregroundStyle(V2Theme.mutedText)
                HStack(spacing: 8) {
                    V2ActionButton(String(localized: "prevention.openResponseActions", defaultValue: "Open Response Actions"), icon: "gearshape", style: .primary) {
                        V2SettingsBridge.openSettings()
                    }
                    V2ActionButton(String(localized: "prevention.triggerSighup", defaultValue: "Trigger SIGHUP"), icon: "arrow.clockwise", style: .secondary,
                                   tooltip: String(localized: "prevention.triggerSighupTooltip", defaultValue: "Reload rules + refresh threat intel feeds")) {
                        Task {
                            let ok = await state.provider.refreshThreatIntel()
                            await MainActor.run {
                                state.showToast(V2Toast(
                                    kind: ok ? .info : .error,
                                    title: ok ? String(localized: "prevention.toastSighupSignaled", defaultValue: "SIGHUP signaled") : String(localized: "prevention.toastSignalFailed", defaultValue: "Signal failed"),
                                    detail: ok ? String(localized: "prevention.toastReloading", defaultValue: "Rules + feeds reloading")
                                              : (state.provider.lastErrorDescription ?? String(localized: "prevention.toastNoDaemon", defaultValue: "no daemon to signal"))
                                ))
                            }
                        }
                    }
                }
            }
            Spacer()
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .v2Panel()
    }

    private var recentActionsCard: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(String(localized: "prevention.recentActionsTitle", defaultValue: "Recent prevention actions")).font(V2Theme.sectionTitle()).foregroundStyle(V2Theme.primaryText)
            if preventionAlerts.isEmpty {
                Text(String(localized: "prevention.recentActionsEmpty", defaultValue: "No prevention actions in the recent alert window. When a rule with a response action fires (kill, block, sinkhole, quarantine), the resulting alert appears here."))
                    .font(V2Theme.body()).foregroundStyle(V2Theme.mutedText)
                    .padding(.vertical, 16)
            } else {
                VStack(spacing: 6) {
                    ForEach(preventionAlerts.prefix(15)) { alert in
                        Button {
                            state.goto(V2NavigationDestination(
                                workspace: .alerts, tab: .alertsOpen, entityId: alert.id
                            ))
                        } label: {
                            HStack(spacing: 10) {
                                V2SeverityDot(alert.severity.chipKind)
                                VStack(alignment: .leading, spacing: 1) {
                                    Text(alert.title)
                                        .font(V2Theme.body())
                                        .foregroundStyle(V2Theme.primaryText)
                                        .lineLimit(1)
                                    Text(String(localized: "prevention.actionRowMeta", defaultValue: "\(alert.process) · \(alert.actionsTaken.joined(separator: ", ")) · \(V2TimeFormat.relative(alert.timestamp))"))
                                        .font(V2Theme.meta())
                                        .foregroundStyle(V2Theme.mutedText)
                                        .lineLimit(1)
                                }
                                Spacer()
                                Image(systemName: "arrow.up.forward")
                                    .scaledSystem(10)
                                    .foregroundStyle(V2Theme.mutedText)
                            }
                            .padding(10)
                            .background(V2Theme.panelBackground)
                            .clipShape(RoundedRectangle(cornerRadius: V2Theme.smallCornerRadius))
                            .contentShape(Rectangle())
                        }
                        .buttonStyle(.plain)
                    }
                }
            }
        }
        .v2Panel()
    }

    private func metricCard(title: String, value: String, trend: String, trendKind: V2ChipKind,
                            icon: String, iconColor: Color) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 6) {
                Image(systemName: icon).foregroundStyle(iconColor).scaledSystem(11, weight: .semibold)
                Text(title.uppercased()).font(V2Theme.cardTitle()).foregroundStyle(V2Theme.mutedText)
            }
            Text(value).scaledSystem(22, weight: .bold).foregroundStyle(V2Theme.primaryText)
            V2StatusChip(trend, kind: trendKind)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .v2Panel()
    }
}
