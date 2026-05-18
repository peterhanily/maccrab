// V2SystemWorkspace.swift
// Spec §7.6 — health, permissions, settings.

import SwiftUI

public struct V2SystemWorkspace: View {
    @ObservedObject var state: V2DashboardState
    @State private var heartbeat: V2HeartbeatSnapshot?
    @State private var permissions: [V2MockPermission] = []
    /// Cached trust-substrate info. Pre-fix the trustSubstrateCard
    /// computed `V2TrustSubstrateInfo.read(...)` inline on every body
    /// re-evaluation — that's two `Data(contentsOf:)` disk reads on
    /// the main thread on every refresh tick (5s) and on every other
    /// state change (tab switch, hover). On a cold cache that's 50-
    /// 200 ms of main-thread blocking, which produced infrequent
    /// beachballs. Now: load once per refresh tick off-main, render
    /// from this @State.
    @State private var trustInfo: V2TrustSubstrateInfo?

    public init(state: V2DashboardState) { self.state = state }

    public var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            V2WorkspaceTabStrip(
                tabs: V2Workspace.system.tabs,
                selected: Binding(
                    get: { state.selectedTabs[.system] ?? .systemHealth },
                    set: { if let v = $0 { state.selectedTabs[.system] = v } }
                )
            )
            tabBody
        }
        .task(id: "\(state.provider.mode):\(state.refreshTick)") {
            // v1.12.6 Wave 9P: write each piece of @State as soon as
            // it resolves, so the System workspace's "metrics
            // freshness" survives the 5s refreshTick cancellation
            // race. heartbeat() reads heartbeat_rich.json (fast on
            // any host); permissions() queries TCC + System Settings
            // adjacencies (can take seconds on a host with a large
            // TCC.db); trust-substrate read is already off-main.
            // Pre-9P all three were gated behind one trailing
            // MainActor.run — if permissions() took longer than the
            // tick interval, the new refreshTick cancelled the body
            // before heartbeat/permissions ever landed in @State.
            // Same root cause as Wave 9G in V2IntelligenceWorkspace.
            let h = await state.provider.heartbeat()
            await MainActor.run { self.heartbeat = h }

            // Read trust-substrate info on a detached task so the
            // disk I/O doesn't block main.
            let dir = state.provider.dataDir ?? "/Library/Application Support/MacCrab"
            let ts = await Task.detached(priority: .userInitiated) {
                V2TrustSubstrateInfo.read(dataDir: dir)
            }.value
            await MainActor.run { self.trustInfo = ts }

            let p = await state.provider.permissions()
            await MainActor.run { self.permissions = p }
        }
    }

    @ViewBuilder
    private var tabBody: some View {
        switch state.selectedTabs[.system] ?? .systemHealth {
        case .systemHealth:      healthTab
        case .systemPermissions: permissionsTab
        case .systemSettings:    settingsTab
        default: healthTab
        }
    }

    // MARK: - Health

    private var healthTab: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                dataSourceCard
                healthSummaryRow
                collectorsTable
                trustSubstrateCard
            }
            .padding(16)
        }
    }

    private var dataSourceCard: some View {
        let isLive = state.provider.mode == .live
        let dirNote = state.provider.dataDir.map { " · \($0)" } ?? ""
        return HStack(spacing: 12) {
            ZStack {
                Circle()
                    .fill((isLive ? V2Theme.healthy : V2Theme.dataAccent).opacity(0.18))
                Image(systemName: isLive ? "cylinder.split.1x2.fill" : "tray.full")
                    .foregroundStyle(isLive ? V2Theme.healthy : V2Theme.dataAccent)
                    .font(.system(size: 16, weight: .semibold))
            }
            .frame(width: 38, height: 38)
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 8) {
                    Text("Data source")
                        .font(.system(size: 13, weight: .semibold))
                        .foregroundStyle(V2Theme.primaryText)
                    V2StatusChip(state.provider.mode.label,
                                 kind: isLive ? .healthy : .info)
                }
                Text(isLive
                     ? "Reading from MacCrabCore stores\(dirNote)"
                     : "Sample / mock data — start the daemon and click Reconnect")
                    .font(V2Theme.meta())
                    .foregroundStyle(V2Theme.mutedText)
                if let err = state.provider.lastErrorDescription {
                    Text("Last error: \(err)")
                        .font(V2Theme.meta())
                        .foregroundStyle(V2Theme.warning)
                        .lineLimit(2)
                }
            }
            Spacer()
            if !isLive {
                V2ActionButton("Reconnect", icon: "arrow.triangle.2.circlepath", style: .secondary) {
                    Task { await state.connectLiveData() }
                }
            }
        }
        .v2Panel()
    }

    /// Heartbeat-driven health row. When the daemon's
    /// heartbeat_rich.json is present and fresh, every card reflects
    /// real values. When absent (no daemon), shows an honest "—".
    private var healthSummaryRow: some View {
        let h = heartbeat
        let collectorCount = h?.collectors.count ?? 0
        let allHealthy = (h?.collectors.allSatisfy { $0.healthy }) ?? false
        let eventsTotal = h.map { fmtCount($0.eventsProcessed) } ?? "—"
        let alertsTotal = h.map { fmtCount($0.alertsEmitted) } ?? "—"
        let memMB = h?.residentMemoryMB.map { "\($0) MB" } ?? "—"
        let rate = h.map { String(format: "%.1f /s", $0.eventsPerSecond1h) } ?? "—"
        return HStack(spacing: 12) {
            metricCard(
                title: "Daemon",
                value: h == nil ? "Offline" : "Running",
                trend: h.map { "uptime \($0.uptimeDisplay)" } ?? "no heartbeat",
                trendKind: h == nil ? .high : .healthy,
                icon: h == nil ? "exclamationmark.shield.fill" : "checkmark.shield.fill",
                iconColor: h == nil ? V2Theme.high : V2Theme.healthy
            )
            metricCard(
                title: "Collectors",
                value: h == nil ? "—" : "\(collectorCount)",
                trend: h == nil ? "—" : (allHealthy ? "all healthy" : "degraded"),
                trendKind: allHealthy ? .healthy : .warning,
                icon: "antenna.radiowaves.left.and.right",
                iconColor: allHealthy ? V2Theme.healthy : V2Theme.warning
            )
            metricCard(
                title: "Event rate",
                value: rate,
                trend: "1h rolling",
                trendKind: .info,
                icon: "waveform.path",
                iconColor: V2Theme.dataAccent
            )
            metricCard(
                title: "Events (lifetime)",
                value: eventsTotal,
                trend: "since boot",
                trendKind: .info,
                icon: "tray.full.fill",
                iconColor: V2Theme.dataAccent
            )
            metricCard(
                title: "Alerts (lifetime)",
                value: alertsTotal,
                trend: "since boot",
                trendKind: h == nil ? .neutral : .info,
                icon: "bell.fill",
                iconColor: V2Theme.high
            )
            metricCard(
                title: "Memory",
                value: memMB,
                trend: "resident",
                trendKind: .healthy,
                icon: "memorychip.fill",
                iconColor: V2Theme.healthy
            )
            // v1.12.6 Wave 9O: surface Wave-9K operator counters,
            // but only when non-zero so a normal-running host's
            // health row isn't cluttered with two extra "0" cards.
            // payload_truncated_total fires when the EventStore
            // 64KB raw_json cap clips an oversized event; non-zero
            // means chatty exec args or large network payloads are
            // landing on the hot path. eslogger_dropped_total is
            // ES-buffer sequence gaps — non-zero means the ring
            // buffer overflowed, which usually requires a daemon
            // restart or tuning.
            if let truncated = h?.payloadTruncatedTotal, truncated > 0 {
                metricCard(
                    title: "Truncations",
                    value: fmtCount(truncated),
                    trend: "64KB cap hits",
                    trendKind: .warning,
                    icon: "scissors",
                    iconColor: V2Theme.warning
                )
            }
            if let dropped = h?.esloggerDroppedTotal, dropped > 0 {
                metricCard(
                    title: "ES drops",
                    value: fmtCount(dropped),
                    trend: "buffer gaps",
                    trendKind: .warning,
                    icon: "exclamationmark.triangle.fill",
                    iconColor: V2Theme.warning
                )
            }
        }
    }

    private func fmtCount(_ n: Int) -> String {
        if n >= 1_000_000 { return String(format: "%.1fM", Double(n) / 1_000_000) }
        if n >= 1_000     { return String(format: "%.1fK", Double(n) / 1_000) }
        return "\(n)"
    }

    /// Collector health table — pulled live from the heartbeat's
    /// `collector_health` array. Empty state shown when no daemon
    /// is reporting (no mock fallback).
    private var collectorsTable: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Collectors").font(V2Theme.sectionTitle()).foregroundStyle(V2Theme.primaryText)
            let rows: [V2CollectorRow] = (heartbeat?.collectors ?? []).map { c in
                V2CollectorRow(
                    id: c.name, name: c.name,
                    healthy: c.healthy, eventCount: c.eventCount,
                    lastTick: c.lastTick, isLive: true
                )
            }
            if rows.isEmpty {
                HStack(spacing: 8) {
                    Image(systemName: "tray").foregroundStyle(V2Theme.mutedText)
                    Text("No daemon heartbeat — start the System Extension or `swift run maccrabd` to see live collector health.")
                        .font(V2Theme.body()).foregroundStyle(V2Theme.mutedText)
                }
                .padding(16)
                .frame(maxWidth: .infinity, alignment: .leading)
                .v2Panel()
            } else {
                V2DataTable(
                    columns: [
                        V2DataColumn(id: "name", title: "Collector", width: .flexible(min: 200)) { c in
                            V2TableCellText(c.name)
                        },
                        V2DataColumn(id: "status", title: "Status", width: .fixed(110)) { c in
                            V2StatusChip(c.healthy ? "Healthy" : "Stalled",
                                         kind: c.healthy ? .healthy : .high)
                        },
                        V2DataColumn(id: "events", title: "Events", width: .fixed(120)) { c in
                            V2TableCellText("\(fmtCount(c.eventCount))",
                                            primary: false, mono: true)
                        },
                        V2DataColumn(id: "last", title: "Last tick", width: .fixed(120)) { c in
                            V2TableCellText(
                                c.lastTick.map(V2TimeFormat.relative) ?? "—",
                                primary: false
                            )
                        },
                    ],
                    items: rows,
                    selection: .constant(nil)
                )
                .frame(minHeight: 380)
            }
        }
    }

    private struct V2CollectorRow: Identifiable, Hashable {
        let id: String
        let name: String
        let healthy: Bool
        let eventCount: Int
        /// nil when the collector has never ticked. Renders as "—".
        let lastTick: Date?
        let isLive: Bool
    }

    private func formatRate(_ rate: Double) -> String {
        if rate >= 1000 { return String(format: "%.1fK", rate / 1000) }
        if rate >= 1    { return String(format: "%.0f", rate) }
        return String(format: "%.2f", rate)
    }
    private func formatLag(_ lag: TimeInterval) -> String {
        if lag < 1     { return String(format: "%.0fms", lag * 1000) }
        if lag < 60    { return String(format: "%.1fs", lag) }
        return String(format: "%.0fm", lag / 60)
    }

    private var trustSubstrateCard: some View {
        // Reads the public key from disk (the daemon writes it under
        // <dataDir>/keys/trace-signing.pub on first run). The
        // activated timestamp comes from the file's mtime, and the
        // mode comes from trust-substrate.json. Falls back to a
        // "Not generated" pill when no key exists.
        //
        // Pre-fix this called `V2TrustSubstrateInfo.read(...)` here in
        // the body, which means two synchronous disk reads on every
        // refresh tick + every body re-evaluation. Now we read once
        // off-main inside the workspace's .task and cache into
        // `self.trustInfo`.
        let info = trustInfo
        return VStack(alignment: .leading, spacing: 12) {
            HStack {
                Text("Trust substrate").font(V2Theme.sectionTitle()).foregroundStyle(V2Theme.primaryText)
                Spacer()
                V2StatusChip(info?.modeLabel ?? "Not generated",
                             kind: info?.modeChipKind ?? .neutral,
                             icon: info == nil ? "questionmark.shield.fill" : "lock.shield.fill")
            }
            Text("MacCrab signs and verifies trace bundles using an ECDSA P-256 keypair. Secure Enclave is preferred; falls back to filesystem when the SE is unavailable. The public key is exported on first run for fleet attestation.")
                .font(V2Theme.body())
                .foregroundStyle(V2Theme.neutral)
            HStack(alignment: .top, spacing: 24) {
                VStack(alignment: .leading, spacing: 1) {
                    Text("FINGERPRINT").font(V2Theme.cardTitle()).foregroundStyle(V2Theme.tertiaryText)
                    Text(info?.fingerprintShort ?? "—")
                        .font(V2Theme.mono())
                        .foregroundStyle(V2Theme.primaryText)
                        .textSelection(.enabled)
                        .help(info?.fingerprintFull ?? "")
                }
                VStack(alignment: .leading, spacing: 1) {
                    Text("KEY SIZE").font(V2Theme.cardTitle()).foregroundStyle(V2Theme.tertiaryText)
                    Text(info?.derSizeLabel ?? "—")
                        .font(V2Theme.mono()).foregroundStyle(V2Theme.primaryText)
                }
                VStack(alignment: .leading, spacing: 1) {
                    Text("ACTIVATED").font(V2Theme.cardTitle()).foregroundStyle(V2Theme.tertiaryText)
                    Text(info?.activatedLabel ?? "—")
                        .font(V2Theme.mono()).foregroundStyle(V2Theme.primaryText)
                }
                if info != nil {
                    Spacer()
                    V2ActionButton("Copy public key", icon: "doc.on.doc", style: .ghost) {
                        if let info {
                            NSPasteboard.general.clearContents()
                            NSPasteboard.general.setString(info.pemString, forType: .string)
                            state.showToast(V2Toast(kind: .success,
                                                    title: "Public key copied",
                                                    detail: "PEM-formatted, paste into your fleet attestation tool"))
                        }
                    }
                }
            }
        }
        .v2Panel()
    }

    // MARK: - Permissions

    private var permissionsTab: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                permissionsSummaryRow
                permissionsTable
            }
            .padding(16)
        }
    }

    private var permissionsSummaryRow: some View {
        let granted = permissions.filter { $0.granted }.count
        let required = permissions.filter { $0.required }.count
        let blockingMissing = permissions.filter { $0.required && !$0.granted }.count
        let optionalMissing = permissions.filter { !$0.required && !$0.granted }.count
        return HStack(spacing: 12) {
            metricCard(title: "Granted", value: "\(granted) / \(permissions.count)",
                       trend: permissions.isEmpty ? "no data" : "required: \(required)",
                       trendKind: permissions.isEmpty ? .neutral : .healthy,
                       icon: "checkmark.shield.fill", iconColor: V2Theme.healthy)
            metricCard(title: "Blocking missing", value: "\(blockingMissing)",
                       trend: blockingMissing == 0 ? "none" : "investigate",
                       trendKind: blockingMissing == 0 ? .healthy : .high,
                       icon: "lock.shield", iconColor: blockingMissing == 0 ? V2Theme.healthy : V2Theme.high)
            metricCard(title: "Optional missing", value: "\(optionalMissing)",
                       trend: optionalMissing == 0 ? "all set" : "feature off",
                       trendKind: .neutral,
                       icon: "questionmark.diamond", iconColor: V2Theme.neutral)
        }
    }

    private var permissionsTable: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("TCC permissions").font(V2Theme.sectionTitle()).foregroundStyle(V2Theme.primaryText)
            V2DataTable(
                columns: [
                    V2DataColumn(id: "name", title: "Service", width: .flexible(min: 220)) { p in
                        V2TableCellText(p.service)
                    },
                    V2DataColumn(id: "req", title: "Required", width: .fixed(110)) { p in
                        V2StatusChip(p.required ? "Yes" : "No",
                                     kind: p.required ? .high : .neutral)
                    },
                    V2DataColumn(id: "granted", title: "Granted", width: .fixed(110)) { p in
                        V2StatusChip(p.granted ? "Yes" : "No",
                                     kind: p.granted ? .healthy : .high)
                    },
                    V2DataColumn(id: "desc", title: "Reason", width: .flexible(min: 280)) { p in
                        V2TableCellText(p.description, primary: false, lineLimit: 2)
                    },
                ],
                items: permissions,
                selection: .constant(nil)
            )
            .frame(minHeight: 280)
            .overlay(alignment: .center) {
                if permissions.isEmpty {
                    Text("No permission probes available — daemon not running.")
                        .font(V2Theme.body()).foregroundStyle(V2Theme.mutedText)
                }
            }
            V2ActionButton("Open Privacy & Security", icon: "arrow.up.right.square", style: .secondary) {
                if let url = URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy") {
                    NSWorkspace.shared.open(url)
                }
            }
        }
    }

    // MARK: - Settings

    /// The v2 Settings tab is intentionally a launcher for the v1
    /// Settings window rather than a duplicated form. Re-implementing
    /// every preference from v1's `SettingsView` would mean two
    /// sources of truth and two sets of bugs. The v1 window is fully
    /// wired to AppStorage + the daemon, and ⌘, opens the same
    /// window from anywhere in the app.
    private var settingsTab: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                openSettingsCard
                settingsShortcutsCard
                quickJumpsCard
            }
            .padding(16)
        }
    }

    private var openSettingsCard: some View {
        HStack(spacing: 14) {
            ZStack {
                Circle().fill(V2Theme.brand.opacity(0.18))
                Image(systemName: "gearshape.fill")
                    .foregroundStyle(V2Theme.brand)
                    .font(.system(size: 18, weight: .bold))
            }
            .frame(width: 44, height: 44)
            VStack(alignment: .leading, spacing: 2) {
                Text("Open MacCrab Settings")
                    .font(.system(size: 15, weight: .semibold))
                    .foregroundStyle(V2Theme.primaryText)
                Text("AI backend, notifications, polling, storage retention, response actions, and integrations all live in the canonical Settings window.")
                    .font(V2Theme.body())
                    .foregroundStyle(V2Theme.mutedText)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer()
            V2ActionButton("Open Settings", icon: "arrow.up.right.square", style: .primary) {
                V2SettingsBridge.openSettings()
            }
        }
        .v2Panel()
    }

    private var settingsShortcutsCard: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Keyboard").font(V2Theme.sectionTitle()).foregroundStyle(V2Theme.primaryText)
            shortcutRow("⌘ ,", "Open Settings (this window's keyboard shortcut)")
            shortcutRow("⌘ ⇧ P", "Command palette · Jump to anything")
            shortcutRow("⌘ K",  "Command palette (alternative)")
            shortcutRow("⌘ 1 – ⌘ 9", "Switch workspaces")
            shortcutRow("⌘ [ / ⌘ ]", "Back / Forward")
            shortcutRow("⌘ R", "Reload events (Events workspace)")
            shortcutRow("Space", "Pause / resume event stream")
            shortcutRow("⌥ ← / ⌥ →", "Previous / next trace (TraceGraph)")
            shortcutRow("Esc", "Close palette / dismiss toast")
        }
        .v2Panel()
    }

    private var quickJumpsCard: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Quick jumps").font(V2Theme.sectionTitle()).foregroundStyle(V2Theme.primaryText)
            HStack {
                V2ActionButton("Permissions", icon: "lock.shield", style: .secondary) {
                    state.selectTab(.systemPermissions)
                }
                V2ActionButton("Health", icon: "waveform.path.ecg", style: .secondary) {
                    state.selectTab(.systemHealth)
                }
                V2ActionButton("Docs", icon: "book.closed.fill", style: .secondary) {
                    state.goto(V2NavigationDestination(workspace: .docs))
                }
                Spacer()
            }
        }
        .v2Panel()
    }

    private func shortcutRow(_ keys: String, _ label: String) -> some View {
        HStack(spacing: 12) {
            Text(keys)
                .font(V2Theme.mono())
                .foregroundStyle(V2Theme.primaryText)
                .padding(.horizontal, 8).padding(.vertical, 4)
                .background(V2Theme.panelBackground)
                .overlay(
                    RoundedRectangle(cornerRadius: 4).stroke(V2Theme.panelBorder, lineWidth: 1)
                )
                .clipShape(RoundedRectangle(cornerRadius: 4))
                .frame(width: 110, alignment: .leading)
            Text(label).font(V2Theme.body()).foregroundStyle(V2Theme.neutral)
            Spacer()
        }
    }

    // MARK: - Shared

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
