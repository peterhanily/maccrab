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
    /// Optimistic per-module toggle overlay, keyed by the heartbeat/payload
    /// module key ("sinkhole" / "network_blocker" / "persistence_guard"). A
    /// pending value wins over the heartbeat-reported state until a later
    /// heartbeat confirms the engine reached it (reconciled in `.task`), so the
    /// switch doesn't visibly snap back during the ~30s apply window.
    @State private var pendingToggles: [String: Bool] = [:]

    init(state: V2DashboardState) { self.state = state }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                preventionStatusStrip
                preventionModulesCard
                summaryRow
                configureCard
                recentActionsCard
            }
            .padding(16)
        }
        .task(id: "\(state.provider.mode):\(state.refreshTick)") {
            // In live mode the provider's toV2Alert hardcodes
            // actionsTaken: [] (see responseHistoryUnavailable), so the
            // 200-alert window would be fetched every tick only to filter
            // down to nothing and never render. Skip it there and fetch
            // just the heartbeat. Mock/offline previews DO carry sample
            // actionsTaken, so keep the wider fetch for them.
            let recent = responseHistoryUnavailable
                ? []
                : await state.provider.alerts(limit: 200)
            let h = await state.provider.heartbeat()
            await MainActor.run {
                self.preventionAlerts = recent.filter { !$0.actionsTaken.isEmpty }
                self.heartbeat = h
                // Drop any optimistic pending toggle the engine has now caught
                // up to (only trust a FRESH heartbeat as ground truth).
                if let p = h?.prevention, !(h?.isStale ?? true) {
                    if pendingToggles["sinkhole"] == p.sinkhole.enabled { pendingToggles["sinkhole"] = nil }
                    if pendingToggles["network_blocker"] == p.networkBlocker.enabled { pendingToggles["network_blocker"] = nil }
                    if pendingToggles["persistence_guard"] == p.persistenceGuard.enabled { pendingToggles["persistence_guard"] = nil }
                }
            }
        }
    }

    /// True only when a FRESH heartbeat reports the prevention block — i.e. we
    /// know each module's real current state. Toggling without a confirmed
    /// current state could enable/disable the wrong thing, so the controls are
    /// disabled otherwise (an honest "we don't know" rather than a live switch
    /// over a stale reading).
    private var canToggle: Bool {
        guard let h = heartbeat, !h.isStale, h.prevention != nil else { return false }
        return true
    }

    /// Binding for one module's toggle. `get` prefers the optimistic pending
    /// value, falling back to the heartbeat-reported `enabled`. `set` fires only
    /// on user interaction (never on a programmatic heartbeat refresh), records
    /// the optimistic value, and drops the inbox request.
    private func toggleBinding(module key: String, enabled: Bool) -> Binding<Bool> {
        Binding(
            get: { pendingToggles[key] ?? enabled },
            set: { newValue in
                pendingToggles[key] = newValue
                pushPrevention(module: key, enabled: newValue)
            }
        )
    }

    private func pushPrevention(module key: String, enabled: Bool) {
        let requested: Bool
        switch key {
        case "sinkhole":          requested = V2DaemonControl.sendPreventionConfig(sinkhole: enabled)
        case "network_blocker":   requested = V2DaemonControl.sendPreventionConfig(networkBlocker: enabled)
        case "persistence_guard": requested = V2DaemonControl.sendPreventionConfig(persistenceGuard: enabled)
        default:                  requested = false
        }
        if requested {
            state.showToast(V2Toast(
                kind: .info,
                title: enabled ? String(localized: "prevention.toastEnabling", defaultValue: "Enabling…")
                               : String(localized: "prevention.toastDisabling", defaultValue: "Disabling…"),
                detail: String(localized: "prevention.toastApplyWindow", defaultValue: "Requested — the enforcing engine applies this within ~30s (requires an administrator).")))
        } else {
            // Honest failure: no inbox dir means no daemon is installed. Roll the
            // optimistic value back so the switch reflects reality.
            pendingToggles[key] = nil
            state.showToast(V2Toast(
                kind: .error,
                title: String(localized: "prevention.toastNoDaemonTitle", defaultValue: "No daemon"),
                detail: String(localized: "prevention.toastNoDaemonBody", defaultValue: "No running MacCrab engine to apply this change.")))
        }
    }

    /// UX-3: live status of the three prevention modules from the daemon
    /// heartbeat. Shows "unavailable" when there's no recent heartbeat (or an
    /// older daemon that doesn't emit the prevention block) rather than a
    /// false reading.
    private var preventionStatusStrip: some View {
        HStack(spacing: 8) {
            if let h = heartbeat, h.isStale {
                // B4: a present-but-STALE heartbeat (>120s) is not a live reading.
                // readFreshest returns snapshots up to 300s old, so during a 2–5 min
                // daemon outage the modules would otherwise paint green "on" while
                // the enforcing daemon is dead. Show a muted "unknown" state instead.
                // (A fully-absent heartbeat still falls through to the
                // "Status unavailable" branch below — that case was already correct.)
                V2StatusChip(String(localized: "prevention.chip.stale", defaultValue: "Prevention status unknown — no daemon heartbeat for \(h.ageSeconds)s"),
                             kind: .neutral, icon: "exclamationmark.triangle")
            } else if let p = heartbeat?.prevention {
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

    /// Per-module enable/disable controls. Each toggle drops an authorized
    /// `prevention-config-*.json` inbox request the root engine applies live to
    /// the DNS-sinkhole / network-blocker / persistence-guard actors (the app
    /// runs as uid-501 and can't mutate root-owned prevention state directly).
    /// Disabled unless a fresh heartbeat confirms the modules' current state.
    private var preventionModulesCard: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(String(localized: "prevention.modulesTitle", defaultValue: "Prevention modules"))
                .font(V2Theme.sectionTitle()).foregroundStyle(V2Theme.primaryText)
            if let p = heartbeat?.prevention, canToggle {
                moduleRow(title: String(localized: "prevention.module.sinkhole", defaultValue: "DNS Sinkhole"),
                          key: "sinkhole", module: p.sinkhole,
                          detail: String(localized: "prevention.module.sinkhole.detail", defaultValue: "Redirects known-malicious domains to 127.0.0.1 via /etc/hosts. Protected domains (Apple, OCSP, resolvers) are never sinkholed."))
                Divider()
                moduleRow(title: String(localized: "prevention.module.networkBlocker", defaultValue: "Network Blocker"),
                          key: "network_blocker", module: p.networkBlocker,
                          detail: String(localized: "prevention.module.networkBlocker.detail", defaultValue: "PF-blocks known-malicious IPs. Loopback / RFC1918 / the default gateway are never blocked."))
                Divider()
                moduleRow(title: String(localized: "prevention.module.persistenceGuard", defaultValue: "Persistence Guard"),
                          key: "persistence_guard", module: p.persistenceGuard,
                          detail: String(localized: "prevention.module.persistenceGuard.detail", defaultValue: "Locks LaunchAgent / LaunchDaemon directories with the system-immutable flag."))
                Text(String(localized: "prevention.modulesFootnote", defaultValue: "Toggles apply to the running engine within ~30s and require an administrator. They apply live only — startup state is set at daemon launch, and while threat-intel feeds are enabled the sinkhole/blocker repopulate on the next feed refresh."))
                    .font(V2Theme.meta()).foregroundStyle(V2Theme.mutedText)
                    .padding(.top, 2)
            } else {
                Text(String(localized: "prevention.modulesUnavailable", defaultValue: "Live module state is unavailable (no recent daemon heartbeat), so these controls are disabled — toggling without a confirmed current state could enable or disable the wrong module."))
                    .font(V2Theme.body()).foregroundStyle(V2Theme.mutedText)
                    .padding(.vertical, 8)
            }
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .v2Panel()
    }

    @ViewBuilder
    private func moduleRow(title: String, key: String,
                           module: V2HeartbeatSnapshot.Prevention.Module, detail: String) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(alignment: .top, spacing: 10) {
                VStack(alignment: .leading, spacing: 2) {
                    Text(title).font(V2Theme.cardTitle()).foregroundStyle(V2Theme.primaryText)
                    Text(detail).font(V2Theme.meta()).foregroundStyle(V2Theme.mutedText)
                }
                Spacer()
                Toggle("", isOn: toggleBinding(module: key, enabled: module.enabled))
                    .labelsHidden()
                    .disabled(!canToggle)
                    .accessibilityLabel(title)
            }
            // Entry detail (view/manage). The daemon heartbeat currently reports
            // COUNTS only — the prevention actors expose no entry-list accessor —
            // so `entries` is empty and we say so honestly. If a future daemon
            // build emits `entries`, the real list renders here automatically.
            if module.enabled {
                if module.entries.isEmpty {
                    Text(module.count == 0
                         ? String(localized: "prevention.module.activeEmpty", defaultValue: "Active — no entries currently enforced.")
                         : String(localized: "prevention.module.countOnly", defaultValue: "\(module.count) enforced — entry list not reported by this daemon build."))
                        .font(V2Theme.meta()).foregroundStyle(V2Theme.mutedText)
                        .padding(.top, 1)
                } else {
                    VStack(alignment: .leading, spacing: 2) {
                        ForEach(module.entries.prefix(20), id: \.self) { entry in
                            Text(entry).font(V2Theme.meta()).foregroundStyle(V2Theme.mutedText).lineLimit(1)
                        }
                        if module.entries.count > 20 {
                            Text(String(localized: "prevention.module.moreEntries", defaultValue: "+ \(module.entries.count - 20) more"))
                                .font(V2Theme.meta()).foregroundStyle(V2Theme.mutedText)
                        }
                    }
                    .padding(.top, 2)
                }
            }
        }
        .padding(.vertical, 4)
    }

    /// B1: the live provider's `toV2Alert` hardcodes `actionsTaken: []` (the
    /// Alert model has no response-action field), so in `.live` mode this surface
    /// can never learn which prevention actions actually fired. Rendering green
    /// "0 / none" cards there is a false "nothing happened" on a protection
    /// surface. Mock/offline previews carry sample actionsTaken, so only the live
    /// build is treated as "not available".
    private var responseHistoryUnavailable: Bool { state.provider.mode == .live }

    private var responseHistoryUnavailableCard: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: "info.circle")
                .foregroundStyle(V2Theme.mutedText)
                .scaledSystem(14)
                .padding(.top, 2)
            VStack(alignment: .leading, spacing: 4) {
                Text(String(localized: "prevention.historyUnavailableTitle", defaultValue: "Response-action history not available"))
                    .font(V2Theme.cardTitle()).foregroundStyle(V2Theme.primaryText)
                Text(String(localized: "prevention.historyUnavailableBody", defaultValue: "This daemon build doesn't report which response actions (kill / block / sinkhole / quarantine) fired per alert, so per-action counts can't be shown. This is a reporting gap — not a confirmation that no actions were taken."))
                    .font(V2Theme.body()).foregroundStyle(V2Theme.mutedText)
            }
            Spacer()
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .v2Panel()
    }

    @ViewBuilder
    private var summaryRow: some View {
        if responseHistoryUnavailable {
            responseHistoryUnavailableCard
        } else {
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
        HStack(spacing: 12) {
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
    }

    private var configureCard: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: "gearshape.fill")
                .foregroundStyle(V2Theme.dataAccent)
                .scaledSystem(14)
                .padding(.top, 2)
            VStack(alignment: .leading, spacing: 6) {
                Text(String(localized: "prevention.configureTitle", defaultValue: "Configure prevention")).font(V2Theme.sectionTitle()).foregroundStyle(V2Theme.primaryText)
                Text(String(localized: "prevention.configureBody", defaultValue: "Per-rule response actions (kill, quarantine, block network, notify, escalate, run script, log) live in `actions.json` under the data dir. Edit them from Settings → Response Actions; the daemon picks up changes on the next SIGHUP (or restart). DNS sinkholing and the network allow/deny blocker are module-level prevention, not per-rule actions."))
                    .font(V2Theme.body()).foregroundStyle(V2Theme.mutedText)
                Text(String(localized: "prevention.ruleDriven", defaultValue: "Response actions are rule-driven: each one fires automatically when its detection rule matches. They are not triggered manually from this screen."))
                    .font(V2Theme.body()).foregroundStyle(V2Theme.mutedText)
                HStack(spacing: 8) {
                    V2ActionButton(String(localized: "prevention.openResponseActions", defaultValue: "Open Response Actions"), icon: "gearshape", style: .primary) {
                        // Deep-link straight to the Response Actions tab —
                        // openSettings() alone lands on whatever tab was last
                        // shown, which is not what this button promises.
                        V2SettingsBridge.openSettings(selectingTab: .responseActions)
                    }
                    V2ActionButton(String(localized: "prevention.triggerSighup", defaultValue: "Trigger SIGHUP"), icon: "arrow.clockwise", style: .secondary,
                                   tooltip: String(localized: "prevention.triggerSighupTooltip", defaultValue: "Reload rules (threat-intel refresh runs only when feeds are enabled)")) {
                        Task {
                            // C3: deliver a REAL SIGHUP. The daemon's handler always
                            // reloads the single/sequence/graph rulesets; it ALSO fires
                            // a one-shot threat-intel refresh, but only when the
                            // threat-intel feeds are enabled (egress is opt-in). The
                            // tooltip/toast are worded to reflect that conditional half
                            // rather than promising a refresh unconditionally. The old
                            // call (refreshThreatIntel) only did the intel half and
                            // never reloaded rules. Detached so the file-IPC write +
                            // pkill fallback never beachball the main thread.
                            let ok = await Task.detached(priority: .userInitiated) {
                                V2DaemonControl.reloadDetectionRules()
                            }.value
                            await MainActor.run {
                                state.showToast(V2Toast(
                                    kind: ok ? .info : .error,
                                    title: ok ? String(localized: "prevention.toastSighupSignaled", defaultValue: "SIGHUP signaled") : String(localized: "prevention.toastSignalFailed", defaultValue: "Signal failed"),
                                    detail: ok ? String(localized: "prevention.toastReloading", defaultValue: "Rules reloading — threat-intel refresh runs only if feeds are enabled")
                                              : String(localized: "prevention.toastNoDaemon", defaultValue: "no daemon to signal")
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
            if responseHistoryUnavailable {
                // B1: don't render an "empty == nothing happened" state when the
                // data source structurally can't report response actions.
                Text(String(localized: "prevention.recentActionsUnavailable", defaultValue: "Response-action history isn't reported by this daemon build, so recent kill / block / sinkhole / quarantine actions can't be listed here. Per-rule response actions still fire automatically — this is a reporting gap only."))
                    .font(V2Theme.body()).foregroundStyle(V2Theme.mutedText)
                    .padding(.vertical, 16)
            } else if preventionAlerts.isEmpty {
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
