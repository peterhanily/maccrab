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

    init(state: V2DashboardState) { self.state = state }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
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
            await MainActor.run {
                self.preventionAlerts = recent.filter { !$0.actionsTaken.isEmpty }
            }
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
            metricCard(title: "Actions (24h)", value: "\(last24h.count)",
                       trend: last24h.isEmpty ? "no triggers" : "review log",
                       trendKind: last24h.isEmpty ? .healthy : .info,
                       icon: "bolt.shield", iconColor: V2Theme.dataAccent)
            metricCard(title: "Process kill", value: "\(killCount)",
                       trend: killCount == 0 ? "none" : "24h",
                       trendKind: killCount == 0 ? .healthy : .warning,
                       icon: "xmark.octagon", iconColor: killCount == 0 ? V2Theme.healthy : V2Theme.high)
            metricCard(title: "Block / sinkhole", value: "\(blockCount)",
                       trend: blockCount == 0 ? "none" : "24h",
                       trendKind: blockCount == 0 ? .healthy : .info,
                       icon: "network.slash", iconColor: V2Theme.dataAccent)
            metricCard(title: "Quarantine", value: "\(quarantineCount)",
                       trend: quarantineCount == 0 ? "none" : "24h",
                       trendKind: quarantineCount == 0 ? .healthy : .warning,
                       icon: "tray.full", iconColor: V2Theme.dataAccent)
        }
    }

    private var configureCard: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: "gearshape.fill")
                .foregroundStyle(V2Theme.dataAccent)
                .font(.system(size: 14))
                .padding(.top, 2)
            VStack(alignment: .leading, spacing: 6) {
                Text("Configure prevention").font(V2Theme.sectionTitle()).foregroundStyle(V2Theme.primaryText)
                Text("Per-rule response actions (kill, block, sinkhole, quarantine, deny-allowlist) live in `actions.json` under the data dir. Edit them from Settings → Response Actions; the daemon picks up changes on the next SIGHUP (or restart).")
                    .font(V2Theme.body()).foregroundStyle(V2Theme.mutedText)
                HStack(spacing: 8) {
                    V2ActionButton("Open Response Actions", icon: "gearshape", style: .primary) {
                        V2SettingsBridge.openSettings()
                    }
                    V2ActionButton("Trigger SIGHUP", icon: "arrow.clockwise", style: .secondary,
                                   tooltip: "Reload rules + refresh threat intel feeds") {
                        Task {
                            let ok = await state.provider.refreshThreatIntel()
                            await MainActor.run {
                                state.showToast(V2Toast(
                                    kind: ok ? .info : .error,
                                    title: ok ? "SIGHUP signaled" : "Signal failed",
                                    detail: ok ? "Rules + feeds reloading"
                                              : (state.provider.lastErrorDescription ?? "no daemon to signal")
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
            Text("Recent prevention actions").font(V2Theme.sectionTitle()).foregroundStyle(V2Theme.primaryText)
            if preventionAlerts.isEmpty {
                Text("No prevention actions in the recent alert window. When a rule with a response action fires (kill, block, sinkhole, quarantine), the resulting alert appears here.")
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
                                    Text("\(alert.process) · \(alert.actionsTaken.joined(separator: ", ")) · \(V2TimeFormat.relative(alert.timestamp))")
                                        .font(V2Theme.meta())
                                        .foregroundStyle(V2Theme.mutedText)
                                        .lineLimit(1)
                                }
                                Spacer()
                                Image(systemName: "arrow.up.forward")
                                    .font(.system(size: 10))
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
                Image(systemName: icon).foregroundStyle(iconColor).font(.system(size: 11, weight: .semibold))
                Text(title.uppercased()).font(V2Theme.cardTitle()).foregroundStyle(V2Theme.mutedText)
            }
            Text(value).font(.system(size: 22, weight: .bold)).foregroundStyle(V2Theme.primaryText)
            V2StatusChip(trend, kind: trendKind)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .v2Panel()
    }
}
