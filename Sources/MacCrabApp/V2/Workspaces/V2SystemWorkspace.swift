// V2SystemWorkspace.swift
// Spec §7.6 — health, permissions, settings.

import SwiftUI
import UniformTypeIdentifiers

public struct V2SystemWorkspace: View {
    @ObservedObject var state: V2DashboardState
    @State private var heartbeat: V2HeartbeatSnapshot?
    @State private var permissions: [V2MockPermission] = []
    /// Cached trust-substrate status. Pre-fix the trustSubstrateCard
    /// computed `V2TrustSubstrateInfo.read(...)` inline on every body
    /// re-evaluation — that's two `Data(contentsOf:)` disk reads on
    /// the main thread on every refresh tick (5s) and on every other
    /// state change (tab switch, hover). On a cold cache that's 50-
    /// 200 ms of main-thread blocking, which produced infrequent
    /// beachballs. Now: load once per refresh tick off-main, render
    /// from this @State. `.status` (vs the old `.read`) also surfaces
    /// the release-install "root-protected, not readable here" case
    /// instead of mislabelling it "Not generated".
    @State private var trustStatus: V2TrustSubstrateInfo.Status = .notGenerated
    /// Owned so its delegate survives the async OS activation callback while
    /// this workspace is on screen (the "Reactivate System Extension" repair
    /// action). Independent of the app's primary manager — sysextd dedups.
    @StateObject private var sysextManager = SystemExtensionManager()

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
                V2TrustSubstrateInfo.status(dataDir: dir)
            }.value
            await MainActor.run { self.trustStatus = ts }

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
                if heartbeat?.esSensorDegraded == true {
                    sensorDegradedBanner
                }
                healthActionsCard
                healthSummaryRow
                collectorsTable
                trustSubstrateCard
            }
            .padding(16)
        }
    }

    /// Engine repair / diagnostics actions — surfaced on Health precisely
    /// because the sensor-degraded and offline states above call for a
    /// recovery affordance. Reactivate re-submits the System Extension
    /// activation (macOS may prompt); Reload rules uses the privileged inbox
    /// (the only cross-uid-safe channel to the root sysext); Export writes a
    /// diagnostics bundle (heartbeat + collector health + permissions + last
    /// error) for issue reports.
    private var healthActionsCard: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(String(localized: "system.actionsSection", defaultValue: "Engine controls"))
                .font(V2Theme.sectionTitle()).foregroundStyle(V2Theme.primaryText)
            Text(String(localized: "system.actionsDesc", defaultValue: "Repair or refresh the detection engine, or export a diagnostics bundle to attach when reporting an issue."))
                .font(V2Theme.body()).foregroundStyle(V2Theme.mutedText)
                .fixedSize(horizontal: false, vertical: true)
            HStack(spacing: 8) {
                V2ActionButton(String(localized: "system.reactivateSysext", defaultValue: "Reactivate System Extension"), icon: "arrow.triangle.2.circlepath", style: .secondary) {
                    sysextManager.activate()
                    state.showToast(V2Toast(
                        kind: .info,
                        title: String(localized: "system.reactivateToastTitle", defaultValue: "Reactivating System Extension"),
                        detail: String(localized: "system.reactivateToastDetail", defaultValue: "macOS may prompt you to approve it in System Settings.")))
                }
                V2ActionButton(String(localized: "system.reloadRules", defaultValue: "Reload rules"), icon: "arrow.clockwise", style: .secondary) {
                    let ok = V2DaemonControl.reloadDetectionRules()
                    state.showToast(ok
                        ? V2Toast(kind: .success,
                                  title: String(localized: "system.reloadRulesOkTitle", defaultValue: "Rule reload requested"),
                                  detail: String(localized: "system.reloadRulesOkDetail", defaultValue: "The engine will reload its rules shortly."))
                        : V2Toast(kind: .error,
                                  title: String(localized: "system.reloadRulesFailTitle", defaultValue: "Couldn't request reload"),
                                  detail: String(localized: "system.reloadRulesFailDetail", defaultValue: "No running engine inbox was found.")))
                }
                V2ActionButton(String(localized: "system.exportDiagnostics", defaultValue: "Export diagnostics"), icon: "square.and.arrow.up", style: .secondary) {
                    exportDiagnostics()
                }
                Spacer()
            }
        }
        .v2Panel()
    }

    /// Write a JSON diagnostics bundle from the currently-loaded health state.
    private func exportDiagnostics() {
        let hb = heartbeat
        let perms = permissions
        let ti = trustStatus.info
        let providerMode = state.provider.mode.label
        let dataDirPath = state.provider.dataDir ?? "—"
        let lastError = state.provider.lastErrorDescription
        let iso = ISO8601DateFormatter()

        var diag: [String: Any] = [
            "generated_at": iso.string(from: Date()),
            "app_version": (Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String) ?? "unknown",
            "provider_mode": providerMode,
            "data_dir": dataDirPath,
        ]
        if let lastError { diag["last_error"] = lastError }
        if let hb {
            // Omit optional keys when absent rather than encoding nil — a nil
            // boxed as Any is not a valid JSON value and would make
            // JSONSerialization throw for the whole bundle.
            var hbDict: [String: Any] = [
                "written_at": iso.string(from: hb.writtenAt),
                "age_seconds": hb.ageSeconds,
                "is_stale": hb.isStale,
                "uptime_seconds": hb.uptimeSeconds,
                "events_processed": hb.eventsProcessed,
                "alerts_emitted": hb.alertsEmitted,
                "sysext_has_fda": hb.sysextHasFDA,
                "events_per_second_1h": hb.eventsPerSecond1h,
                "payload_truncated_total": hb.payloadTruncatedTotal,
                "eslogger_dropped_total": hb.esloggerDroppedTotal,
                "es_sensor_degraded": hb.esSensorDegraded,
            ]
            if let mem = hb.residentMemoryMB { hbDict["resident_memory_mb"] = mem }
            if let sev = hb.esSensorDegradedSeverity { hbDict["es_sensor_degraded_severity"] = sev }
            diag["heartbeat"] = hbDict
            diag["collectors"] = hb.collectors.map { c -> [String: Any] in
                var m: [String: Any] = ["name": c.name, "event_count": c.eventCount, "healthy": c.healthy]
                if let lt = c.lastTick { m["last_tick"] = iso.string(from: lt) }
                return m
            }
        }
        diag["permissions"] = perms.map { p -> [String: Any] in
            ["service": p.service, "granted": p.granted, "required": p.required, "detail": p.description]
        }
        if let ti {
            diag["trust_substrate"] = ["mode": ti.modeLabel, "fingerprint": ti.fingerprintFull]
        }

        let panel = NSSavePanel()
        panel.title = String(localized: "system.exportDiagnosticsPanelTitle", defaultValue: "Export diagnostics")
        panel.allowedContentTypes = [.json]
        panel.allowsOtherFileTypes = true
        let fmt = DateFormatter()
        fmt.dateFormat = "yyyy-MM-dd-HHmm"
        fmt.timeZone = .current
        panel.nameFieldStringValue = "maccrab-diagnostics-\(fmt.string(from: Date())).json"
        panel.begin { response in
            guard response == .OK, let url = panel.url else { return }
            DispatchQueue.global(qos: .userInitiated).async {
                var ok = false
                if let data = try? JSONSerialization.data(withJSONObject: diag, options: [.prettyPrinted, .sortedKeys]) {
                    ok = (try? data.write(to: url, options: .atomic)) != nil
                }
                DispatchQueue.main.async {
                    state.showToast(ok
                        ? V2Toast(kind: .success,
                                  title: String(localized: "system.exportDiagnosticsOkTitle", defaultValue: "Diagnostics exported"),
                                  detail: url.lastPathComponent)
                        : V2Toast(kind: .error,
                                  title: String(localized: "system.exportDiagnosticsFailTitle", defaultValue: "Export failed"),
                                  detail: url.path))
                }
            }
        }
    }

    /// v1.21.4 Phase-1 D2: prominent advisory banner when the ES sensor is
    /// dropping telemetry under a file-event flood (possible evasion). Shown
    /// only while the heartbeat reports the degraded state; advisory only —
    /// MacCrab never auto-throttles or auto-mutes in response.
    private var sensorDegradedBanner: some View {
        let isBenign = (heartbeat?.esSensorDegradedSeverity == "low")
        let accent = isBenign ? V2Theme.warning : V2Theme.high
        let title = isBenign
            ? String(localized: "system.sensorDegradedBenignTitle", defaultValue: "Protection degraded (benign attribution)")
            : String(localized: "system.sensorDegradedTitle", defaultValue: "Protection degraded — possible telemetry-drop evasion")
        let detail = heartbeat?.esSensorDegradedDetail
            ?? String(localized: "system.sensorDegradedDefaultDetail", defaultValue: "A file-event flood is spiking above baseline while the kernel is dropping ES messages, starving process/exec coverage.")
        return HStack(alignment: .top, spacing: 12) {
            ZStack {
                Circle().fill(accent.opacity(0.18))
                Image(systemName: "exclamationmark.shield.fill")
                    .foregroundStyle(accent)
                    .scaledSystem(16, weight: .semibold)
            }
            .frame(width: 38, height: 38)
            VStack(alignment: .leading, spacing: 4) {
                HStack(spacing: 8) {
                    Text(title)
                        .scaledSystem(13, weight: .semibold)
                        .foregroundStyle(V2Theme.primaryText)
                    V2StatusChip(isBenign
                        ? String(localized: "system.sensorDegradedChipLow", defaultValue: "Advisory")
                        : String(localized: "system.sensorDegradedChipHigh", defaultValue: "Degraded"),
                        kind: isBenign ? .warning : .degraded)
                }
                Text(detail)
                    .font(V2Theme.meta())
                    .foregroundStyle(V2Theme.mutedText)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer()
        }
        .v2Panel()
    }

    private var dataSourceCard: some View {
        let isLive = state.provider.mode == .live
        let dirNote = state.provider.dataDir.map { " · \($0)" } ?? ""
        let subtitle: String
        switch state.provider.mode {
        case .live:    subtitle = String(localized: "system.dataSourceLive", defaultValue: "Reading from MacCrabCore stores\(dirNote)")
        case .offline: subtitle = String(localized: "system.dataSourceOffline", defaultValue: "No daemon data yet — start or approve the daemon, then click Reconnect")
        case .mock:    subtitle = String(localized: "system.dataSourceMock", defaultValue: "Sample / mock data (dev build) — start the daemon and click Reconnect")
        }
        return HStack(spacing: 12) {
            ZStack {
                Circle()
                    .fill((isLive ? V2Theme.healthy : V2Theme.dataAccent).opacity(0.18))
                Image(systemName: isLive ? "cylinder.split.1x2.fill" : "tray.full")
                    .foregroundStyle(isLive ? V2Theme.healthy : V2Theme.dataAccent)
                    .scaledSystem(16, weight: .semibold)
            }
            .frame(width: 38, height: 38)
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 8) {
                    Text(String(localized: "system.dataSourceTitle", defaultValue: "Data source"))
                        .scaledSystem(13, weight: .semibold)
                        .foregroundStyle(V2Theme.primaryText)
                    V2StatusChip(state.provider.mode.label,
                                 kind: isLive ? .healthy : .info)
                }
                Text(subtitle)
                    .font(V2Theme.meta())
                    .foregroundStyle(V2Theme.mutedText)
                if let err = state.provider.lastErrorDescription {
                    Text(String(localized: "system.lastError", defaultValue: "Last error: \(err)"))
                        .font(V2Theme.meta())
                        .foregroundStyle(V2Theme.warning)
                        .lineLimit(2)
                }
            }
            Spacer()
            if !isLive {
                V2ActionButton(String(localized: "system.reconnect", defaultValue: "Reconnect"), icon: "arrow.triangle.2.circlepath", style: .secondary) {
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
        // v1.21.4 B2/B3: `readFreshest()` only nils heartbeats >300s old, so a
        // 120–300s-old heartbeat is returned non-nil. Gate live/green on the
        // canonical 120s `isStale`, not on the snapshot merely existing — a
        // 2–5 min outage must read "Stale", not "Running".
        let stale = h?.isStale ?? false          // present but >120s old
        let live = h != nil && !stale
        let staleAgeMin = (h?.ageSeconds ?? 0) / 60
        // B3: `[].allSatisfy` is vacuously true — zero collectors = no event
        // sources = NOT healthy. Only green on a fresh, non-empty, all-healthy set.
        let collectors = h?.collectors ?? []
        let collectorCount = collectors.count
        let collectorsAllHealthy = !collectors.isEmpty && collectors.allSatisfy { $0.healthy }
        let collectorsKind: V2ChipKind
        let collectorsTrend: String
        if h == nil {
            collectorsKind = .neutral
            collectorsTrend = "—"
        } else if collectorCount == 0 {
            collectorsKind = .warning
            collectorsTrend = String(localized: "system.collectorsNone", defaultValue: "no event sources")
        } else if stale {
            collectorsKind = .warning
            collectorsTrend = String(localized: "system.collectorsStale", defaultValue: "stale")
        } else if collectorsAllHealthy {
            collectorsKind = .healthy
            collectorsTrend = String(localized: "system.collectorsAllHealthy", defaultValue: "all healthy")
        } else {
            collectorsKind = .warning
            collectorsTrend = String(localized: "system.collectorsDegraded", defaultValue: "degraded")
        }
        let eventsTotal = h.map { fmtCount($0.eventsProcessed) } ?? "—"
        let alertsTotal = h.map { fmtCount($0.alertsEmitted) } ?? "—"
        let memMB = h?.residentMemoryMB.map { "\($0) MB" } ?? "—"
        let rate = h.map { String(format: "%.1f /s", $0.eventsPerSecond1h) } ?? "—"
        // When the heartbeat is stale, every "since boot / resident / 1h" card
        // below is a frozen snapshot — flag it rather than present it as live.
        let staleSuffix = stale ? " · " + String(localized: "system.metricStale", defaultValue: "stale") : ""
        func liveKind(_ base: V2ChipKind) -> V2ChipKind { stale ? .warning : base }
        // Up to 8 metric cards. A plain HStack crushed them all into one
        // non-wrapping row on a narrow window; the flow grid wraps to a 4-column
        // masonry (as the Overview dashboard does) so each card keeps a readable
        // width and the row reflows instead of truncating.
        return V2FlowGridLayout(columns: 4, spacing: 12, rowSpacing: 12) {
            metricCard(
                title: String(localized: "system.metricDaemon", defaultValue: "Daemon"),
                value: h == nil
                    ? String(localized: "system.daemonOffline", defaultValue: "Offline")
                    : (stale
                        ? String(localized: "system.daemonStale", defaultValue: "Stale (\(staleAgeMin)m ago)")
                        : String(localized: "system.daemonRunning", defaultValue: "Running")),
                trend: h == nil
                    ? String(localized: "system.daemonNoHeartbeat", defaultValue: "no heartbeat")
                    : (stale
                        ? String(localized: "system.daemonStaleTrend", defaultValue: "no recent heartbeat")
                        : (h.map { String(localized: "system.daemonUptime", defaultValue: "uptime \($0.uptimeDisplay)") } ?? "")),
                trendKind: h == nil ? .high : (stale ? .warning : .healthy),
                icon: live ? "checkmark.shield.fill" : "exclamationmark.shield.fill",
                iconColor: h == nil ? V2Theme.high : (stale ? V2Theme.warning : V2Theme.healthy)
            )
            metricCard(
                title: String(localized: "system.metricCollectors", defaultValue: "Collectors"),
                value: h == nil ? "—" : "\(collectorCount)",
                trend: collectorsTrend,
                trendKind: collectorsKind,
                icon: "antenna.radiowaves.left.and.right",
                iconColor: collectorsKind.color
            )
            metricCard(
                title: String(localized: "system.metricEventRate", defaultValue: "Event rate"),
                value: rate,
                trend: String(localized: "system.eventRate1h", defaultValue: "1h rolling") + staleSuffix,
                trendKind: liveKind(.info),
                icon: "waveform.path",
                iconColor: V2Theme.dataAccent
            )
            metricCard(
                title: String(localized: "system.metricEventsLifetime", defaultValue: "Events (lifetime)"),
                value: eventsTotal,
                trend: String(localized: "system.sinceBootEvents", defaultValue: "since boot") + staleSuffix,
                trendKind: liveKind(.info),
                icon: "tray.full.fill",
                iconColor: V2Theme.dataAccent
            )
            metricCard(
                title: String(localized: "system.metricAlertsLifetime", defaultValue: "Alerts (lifetime)"),
                value: alertsTotal,
                trend: String(localized: "system.sinceBootAlerts", defaultValue: "since boot") + staleSuffix,
                trendKind: h == nil ? .neutral : liveKind(.info),
                icon: "bell.fill",
                iconColor: V2Theme.high
            )
            metricCard(
                title: String(localized: "system.metricMemory", defaultValue: "Memory"),
                value: memMB,
                trend: String(localized: "system.memoryResident", defaultValue: "resident") + staleSuffix,
                trendKind: liveKind(.healthy),
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
                    title: String(localized: "system.metricTruncations", defaultValue: "Truncations"),
                    value: fmtCount(truncated),
                    trend: String(localized: "system.truncationsCapHits", defaultValue: "64KB cap hits"),
                    trendKind: .warning,
                    icon: "scissors",
                    iconColor: V2Theme.warning
                )
            }
            if let dropped = h?.esloggerDroppedTotal, dropped > 0 {
                metricCard(
                    title: String(localized: "system.metricEsDrops", defaultValue: "ES drops"),
                    value: fmtCount(dropped),
                    trend: String(localized: "system.esDropsBufferGaps", defaultValue: "buffer gaps"),
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
            Text(String(localized: "system.collectorsSection", defaultValue: "Collectors")).font(V2Theme.sectionTitle()).foregroundStyle(V2Theme.primaryText)
            let rows: [V2CollectorRow] = (heartbeat?.collectors ?? []).map { c in
                V2CollectorRow(
                    id: c.name, name: c.name,
                    healthy: c.healthy, eventCount: c.eventCount,
                    lastTick: c.lastTick
                )
            }
            if rows.isEmpty {
                HStack(spacing: 8) {
                    Image(systemName: "tray").foregroundStyle(V2Theme.mutedText)
                    Text(String(localized: "system.collectorsEmpty", defaultValue: "No daemon heartbeat — start the System Extension or `swift run maccrabd` to see live collector health."))
                        .font(V2Theme.body()).foregroundStyle(V2Theme.mutedText)
                }
                .padding(16)
                .frame(maxWidth: .infinity, alignment: .leading)
                .v2Panel()
            } else {
                V2DataTable(
                    columns: [
                        V2DataColumn(id: "name", title: String(localized: "system.colCollector", defaultValue: "Collector"), width: .flexible(min: 200)) { c in
                            V2TableCellText(c.name)
                        },
                        V2DataColumn(id: "status", title: String(localized: "system.colStatus", defaultValue: "Status"), width: .fixed(110)) { c in
                            V2StatusChip(c.healthy ? String(localized: "system.collectorHealthy", defaultValue: "Healthy") : String(localized: "system.collectorStalled", defaultValue: "Stalled"),
                                         kind: c.healthy ? .healthy : .high)
                        },
                        V2DataColumn(id: "events", title: String(localized: "system.colEvents", defaultValue: "Events"), width: .fixed(120)) { c in
                            V2TableCellText("\(fmtCount(c.eventCount))",
                                            primary: false, mono: true)
                        },
                        V2DataColumn(id: "last", title: String(localized: "system.colLastTick", defaultValue: "Last tick"), width: .fixed(120)) { c in
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
    }

    private var trustSubstrateCard: some View {
        // Reads the public key from disk (the daemon writes it under
        // <dataDir>/keys/trace-signing.pub on first run). The
        // activated timestamp comes from the file's mtime, and the
        // mode comes from trust-substrate.json. Shows "Managed by
        // engine" when the key is root-protected (unreadable from the
        // uid-501 app) and "Not generated" only when no key exists.
        //
        // Pre-fix this called `V2TrustSubstrateInfo.read(...)` here in
        // the body, which means two synchronous disk reads on every
        // refresh tick + every body re-evaluation. Now we read once
        // off-main inside the workspace's .task and cache into
        // `self.trustStatus`.
        let info = trustStatus.info
        // Chip reflects the three states honestly: the real mode label when the
        // public key is readable; "Managed by engine" when the key exists but is
        // root-protected (release: `keys/` is 0o700 root-owned, so the uid-501
        // app can't read the 0o644 pubkey inside it); and "Not generated" only
        // when there is genuinely no key. Pre-fix the middle case rendered as
        // "Not generated", so this card sat permanently dead on every release.
        let chipLabel: String
        let chipKind: V2ChipKind
        let chipIcon: String
        switch trustStatus {
        case .available(let i):
            chipLabel = i.modeLabel; chipKind = i.modeChipKind; chipIcon = "lock.shield.fill"
        case .managedByEngine:
            chipLabel = String(localized: "system.trustManagedByEngine", defaultValue: "Managed by engine")
            chipKind = .info; chipIcon = "lock.shield.fill"
        case .notGenerated:
            chipLabel = String(localized: "system.trustNotGenerated", defaultValue: "Not generated")
            chipKind = .neutral; chipIcon = "questionmark.shield.fill"
        }
        return VStack(alignment: .leading, spacing: 12) {
            HStack {
                Text(String(localized: "system.trustSubstrateSection", defaultValue: "Trust substrate")).font(V2Theme.sectionTitle()).foregroundStyle(V2Theme.primaryText)
                Spacer()
                V2StatusChip(chipLabel, kind: chipKind, icon: chipIcon)
            }
            Text(String(localized: "system.trustSubstrateDesc", defaultValue: "MacCrab signs and verifies trace bundles using an ECDSA P-256 keypair. Secure Enclave is preferred; falls back to filesystem when the SE is unavailable. The public key is exported on first run for fleet attestation."))
                .font(V2Theme.body())
                .foregroundStyle(V2Theme.neutral)
            if case .managedByEngine = trustStatus {
                // Honest explanation so "no detail below" doesn't read as "no key".
                // The engine (root) owns the signing key; the menubar app (uid 501)
                // legitimately can't read it. Root can view it from the CLI.
                Text(String(localized: "system.trustManagedDetail",
                            defaultValue: "The signing key is owned and protected by the engine (root), so it isn't readable from the app on this install. To view it, run: sudo maccrabctl debug trust-substrate"))
                    .font(V2Theme.meta())
                    .foregroundStyle(V2Theme.mutedText)
                    .fixedSize(horizontal: false, vertical: true)
                    .textSelection(.enabled)
            }
            HStack(alignment: .top, spacing: 24) {
                VStack(alignment: .leading, spacing: 1) {
                    Text(String(localized: "system.trustFingerprint", defaultValue: "FINGERPRINT")).font(V2Theme.cardTitle()).foregroundStyle(V2Theme.tertiaryText)
                    Text(info?.fingerprintShort ?? "—")
                        .font(V2Theme.mono())
                        .foregroundStyle(V2Theme.primaryText)
                        .textSelection(.enabled)
                        .help(info?.fingerprintFull ?? "")
                }
                VStack(alignment: .leading, spacing: 1) {
                    Text(String(localized: "system.trustKeySize", defaultValue: "KEY SIZE")).font(V2Theme.cardTitle()).foregroundStyle(V2Theme.tertiaryText)
                    Text(info?.derSizeLabel ?? "—")
                        .font(V2Theme.mono()).foregroundStyle(V2Theme.primaryText)
                }
                VStack(alignment: .leading, spacing: 1) {
                    Text(String(localized: "system.trustActivated", defaultValue: "ACTIVATED")).font(V2Theme.cardTitle()).foregroundStyle(V2Theme.tertiaryText)
                    Text(info?.activatedLabel ?? "—")
                        .font(V2Theme.mono()).foregroundStyle(V2Theme.primaryText)
                }
                if info != nil {
                    Spacer()
                    V2ActionButton(String(localized: "system.copyPublicKey", defaultValue: "Copy public key"), icon: "doc.on.doc", style: .ghost) {
                        if let info {
                            NSPasteboard.general.clearContents()
                            NSPasteboard.general.setString(info.pemString, forType: .string)
                            state.showToast(V2Toast(kind: .success,
                                                    title: String(localized: "system.publicKeyCopiedTitle", defaultValue: "Public key copied"),
                                                    detail: String(localized: "system.publicKeyCopiedDetail", defaultValue: "PEM-formatted, paste into your fleet attestation tool")))
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
        // Engine (System Extension) Full Disk Access — the authoritative signal
        // is the heartbeat boolean the sysext writes after probing itself, NOT
        // the app-side TCC dump above (which is the menubar app's own grants).
        let hb = heartbeat
        let engineFDAValue: String
        let engineFDAKind: V2ChipKind
        let engineFDATrend: String
        if hb == nil {
            engineFDAValue = "—"; engineFDAKind = .neutral
            engineFDATrend = String(localized: "system.engineFDANoData", defaultValue: "no heartbeat")
        } else if hb?.isStale == true {
            engineFDAValue = String(localized: "system.engineFDAUnknown", defaultValue: "Unknown")
            engineFDAKind = .warning
            engineFDATrend = String(localized: "system.engineFDAStale", defaultValue: "last known")
        } else if hb?.sysextHasFDA == true {
            engineFDAValue = String(localized: "system.engineFDAGranted", defaultValue: "Granted")
            engineFDAKind = .healthy
            engineFDATrend = String(localized: "system.engineFDASysext", defaultValue: "system extension")
        } else {
            engineFDAValue = String(localized: "system.engineFDAMissing", defaultValue: "Missing")
            engineFDAKind = .high
            engineFDATrend = String(localized: "system.engineFDANoEvents", defaultValue: "engine can't read events")
        }
        return HStack(spacing: 12) {
            metricCard(title: String(localized: "system.permGranted", defaultValue: "Granted"), value: "\(granted) / \(permissions.count)",
                       trend: permissions.isEmpty ? String(localized: "system.permNoData", defaultValue: "no data") : String(localized: "system.permRequiredCount", defaultValue: "required: \(required)"),
                       trendKind: permissions.isEmpty ? .neutral : .healthy,
                       icon: "checkmark.shield.fill", iconColor: V2Theme.healthy)
            metricCard(title: String(localized: "system.engineFDA", defaultValue: "Engine FDA"), value: engineFDAValue,
                       trend: engineFDATrend, trendKind: engineFDAKind,
                       icon: "externaldrive.fill", iconColor: engineFDAKind.color)
            metricCard(title: String(localized: "system.permBlockingMissing", defaultValue: "Blocking missing"), value: "\(blockingMissing)",
                       trend: blockingMissing == 0 ? String(localized: "system.permBlockingNone", defaultValue: "none") : String(localized: "system.permBlockingInvestigate", defaultValue: "investigate"),
                       trendKind: blockingMissing == 0 ? .healthy : .high,
                       icon: "lock.shield", iconColor: blockingMissing == 0 ? V2Theme.healthy : V2Theme.high)
            metricCard(title: String(localized: "system.permOptionalMissing", defaultValue: "Optional missing"), value: "\(optionalMissing)",
                       trend: optionalMissing == 0 ? String(localized: "system.permOptionalAllSet", defaultValue: "all set") : String(localized: "system.permOptionalFeatureOff", defaultValue: "feature off"),
                       trendKind: .neutral,
                       icon: "questionmark.diamond", iconColor: V2Theme.neutral)
        }
    }

    private var permissionsTable: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(String(localized: "system.tccSection", defaultValue: "TCC permissions")).font(V2Theme.sectionTitle()).foregroundStyle(V2Theme.primaryText)
            V2DataTable(
                columns: [
                    V2DataColumn(id: "name", title: String(localized: "system.colService", defaultValue: "Service"), width: .flexible(min: 220)) { p in
                        V2TableCellText(p.service)
                    },
                    V2DataColumn(id: "req", title: String(localized: "system.colRequired", defaultValue: "Required"), width: .fixed(110)) { p in
                        V2StatusChip(p.required ? String(localized: "system.reqYes", defaultValue: "Yes") : String(localized: "system.reqNo", defaultValue: "No"),
                                     kind: p.required ? .high : .neutral)
                    },
                    V2DataColumn(id: "granted", title: String(localized: "system.colGranted", defaultValue: "Granted"), width: .fixed(110)) { p in
                        V2StatusChip(p.granted ? String(localized: "system.grantedYes", defaultValue: "Yes") : String(localized: "system.grantedNo", defaultValue: "No"),
                                     kind: p.granted ? .healthy : .high)
                    },
                    V2DataColumn(id: "fix", title: String(localized: "system.colFix", defaultValue: ""), width: .fixed(90)) { p in
                        if p.required && !p.granted {
                            V2ActionButton(String(localized: "system.fixPermission", defaultValue: "Fix"),
                                           icon: "arrow.up.forward.app", style: .secondary, size: .compact) {
                                openPermissionSettings(for: p.service)
                            }
                        }
                    },
                    V2DataColumn(id: "desc", title: String(localized: "system.colReason", defaultValue: "Reason"), width: .flexible(min: 280)) { p in
                        V2TableCellText(p.description, primary: false, lineLimit: 2)
                    },
                ],
                items: permissions,
                selection: .constant(nil)
            )
            .frame(minHeight: 280)
            .overlay(alignment: .center) {
                if permissions.isEmpty {
                    Text(String(localized: "system.tccEmpty", defaultValue: "No permission probes available — daemon not running."))
                        .font(V2Theme.body()).foregroundStyle(V2Theme.mutedText)
                }
            }
            V2ActionButton(String(localized: "system.openPrivacySecurity", defaultValue: "Open Privacy & Security"), icon: "arrow.up.right.square", style: .secondary) {
                openPermissionSettings(for: nil)
            }
        }
    }

    /// Deep-link to the specific System Settings › Privacy pane for a TCC
    /// service (or the Privacy root when unmapped / nil). `service` is the
    /// pretty label produced by V2LiveDataProvider.prettyTCCService.
    private func openPermissionSettings(for service: String?) {
        let base = "x-apple.systempreferences:com.apple.preference.security?"
        let anchor = service.flatMap(permissionAnchor(for:)) ?? "Privacy"
        if let url = URL(string: base + anchor) {
            NSWorkspace.shared.open(url)
        }
    }

    private func permissionAnchor(for service: String) -> String? {
        switch service {
        case "Full Disk Access":  return "Privacy_AllFiles"
        case "Accessibility":     return "Privacy_Accessibility"
        case "Input Monitoring":  return "Privacy_ListenEvent"
        case "Screen Recording":  return "Privacy_ScreenCapture"
        case "Camera":            return "Privacy_Camera"
        case "Microphone":        return "Privacy_Microphone"
        case "Contacts":          return "Privacy_Contacts"
        case "Calendar":          return "Privacy_Calendars"
        case "Photos":            return "Privacy_Photos"
        case "Location Services": return "Privacy_LocationServices"
        // Endpoint Security Client has no dedicated Privacy pane (it's granted
        // via System Extension approval, not a TCC toggle) → Privacy root.
        default:                  return nil
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
                    .scaledSystem(18, weight: .bold)
            }
            .frame(width: 44, height: 44)
            VStack(alignment: .leading, spacing: 2) {
                Text(String(localized: "system.openSettingsTitle", defaultValue: "Open MacCrab Settings"))
                    .scaledSystem(15, weight: .semibold)
                    .foregroundStyle(V2Theme.primaryText)
                Text(String(localized: "system.openSettingsDesc", defaultValue: "AI backend, notifications, polling, storage retention, response actions, and integrations all live in the canonical Settings window."))
                    .font(V2Theme.body())
                    .foregroundStyle(V2Theme.mutedText)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer()
            V2ActionButton(String(localized: "system.openSettingsButton", defaultValue: "Open Settings"), icon: "arrow.up.right.square", style: .primary) {
                V2SettingsBridge.openSettings()
            }
        }
        .v2Panel()
    }

    private var settingsShortcutsCard: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(String(localized: "system.keyboardSection", defaultValue: "Keyboard")).font(V2Theme.sectionTitle()).foregroundStyle(V2Theme.primaryText)
            shortcutRow("⌘ ,", String(localized: "system.shortcutOpenSettings", defaultValue: "Open Settings (this window's keyboard shortcut)"))
            shortcutRow("⌘ ⇧ P", String(localized: "system.shortcutPalette", defaultValue: "Command palette · Jump to anything"))
            shortcutRow("⌘ K",  String(localized: "system.shortcutPaletteAlt", defaultValue: "Command palette (alternative)"))
            shortcutRow("⌘ 1 – ⌘ 9", String(localized: "system.shortcutSwitchWorkspaces", defaultValue: "Switch workspaces"))
            shortcutRow("⌘ [ / ⌘ ]", String(localized: "system.shortcutBackForward", defaultValue: "Back / Forward"))
            shortcutRow("⌘ R", String(localized: "system.shortcutReloadEvents", defaultValue: "Reload events (Events workspace)"))
            shortcutRow("Space", String(localized: "system.shortcutPauseResume", defaultValue: "Pause / resume event stream"))
            shortcutRow("⌥ ← / ⌥ →", String(localized: "system.shortcutPrevNextTrace", defaultValue: "Previous / next trace (TraceGraph)"))
            shortcutRow("Esc", String(localized: "system.shortcutClosePalette", defaultValue: "Close palette / dismiss toast"))
        }
        .v2Panel()
    }

    private var quickJumpsCard: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(String(localized: "system.quickJumpsSection", defaultValue: "Quick jumps")).font(V2Theme.sectionTitle()).foregroundStyle(V2Theme.primaryText)
            HStack {
                V2ActionButton(String(localized: "system.quickJumpPermissions", defaultValue: "Permissions"), icon: "lock.shield", style: .secondary) {
                    state.selectTab(.systemPermissions)
                }
                V2ActionButton(String(localized: "system.quickJumpHealth", defaultValue: "Health"), icon: "waveform.path.ecg", style: .secondary) {
                    state.selectTab(.systemHealth)
                }
                V2ActionButton(String(localized: "system.quickJumpDocs", defaultValue: "Docs"), icon: "book.closed.fill", style: .secondary) {
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
