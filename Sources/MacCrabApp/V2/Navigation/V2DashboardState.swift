// V2DashboardState.swift
// MacCrabApp — Dashboard v2
//
// Top-level mutable state for the v2 shell.
//
// Phase 1: workspace + tab persistence.
// Phase 3: navigation history (back/forward), recent destinations,
// saved views, per-workspace filters, toast queue, deep-link entry.

import SwiftUI
import Combine

@MainActor
public final class V2DashboardState: ObservableObject {

    // MARK: - Core navigation

    @Published public var currentWorkspace: V2Workspace
    @Published public var paletteOpen: Bool = false
    @Published public var statusMessage: String? = nil
    @Published public var selectedTabs: [V2Workspace: V2WorkspaceTab]
    @Published public var selectedEntities: [String: String] = [:]

    // MARK: - Phase 3: history + recents + saved + toasts

    @Published public var history = V2NavigationHistory()
    @Published public var recentDestinations: [V2NavigationDestination] = []
    @Published public var toast: V2Toast? = nil

    /// Cross-workspace intent: bumped to navigate to Detection › Rules
    /// AND open the New Rule wizard in one click. Workspaces consume +
    /// reset it. Pre-fix the Overview "Create rule" button only
    /// navigated; the user still had to click "+ New rule" inside.
    @Published public var presentNewRuleTick: Int = 0

    /// Cross-tab intent: a scanner plugin id the user asked to "Run on this Mac"
    /// from the Catalog. The Scans tab consumes it (runs via its shared
    /// KitRunner through the existing consent gate) and resets it to nil.
    @Published public var pendingForensicsRunPluginID: String? = nil

    /// Current data source. In a release build this starts as the honest
    /// empty/offline provider (V2OfflineDataProvider) and flips to live once
    /// `connectLiveData()` succeeds; a DEBUG/dev build starts on the mock
    /// fixtures instead. A release NEVER renders fabricated [DEMO] data.
    @Published public var provider: V2DataProvider = {
        #if DEBUG
        return V2MockDataProvider()
        #else
        return V2OfflineDataProvider()
        #endif
    }()

    /// Synchronous caches of recent entities for the command palette's
    /// alert:/rule:/trace: lookups. The palette filter is sync but the live
    /// provider is async, so these are refreshed when the palette opens (and
    /// on each auto-refresh tick) and read synchronously by entityLookup.
    /// Empty until the live provider populates them. (In a DEBUG build the
    /// palette falls back to V2MockRepository fixtures while in mock mode.)
    @Published public var paletteAlerts: [V2MockAlert] = []
    @Published public var paletteRules: [V2MockRule] = []
    @Published public var paletteTraces: [V2MockTrace] = []

    /// Populate the palette entity caches from the live provider with bounded,
    /// concurrent fetches. Safe to call on palette open + on refresh ticks.
    public func refreshPaletteEntities() async {
        async let a = provider.alerts(limit: 200)
        async let r = provider.rules()
        async let t = provider.traces(limit: 50)
        let (alerts, rules, traces) = await (a, r, t)
        self.paletteAlerts = alerts
        self.paletteRules = rules
        self.paletteTraces = traces
    }

    /// Bumped by the auto-refresh timer; workspaces key their
    /// `.task` modifiers off this so they re-fetch on each tick.
    @Published public var refreshTick: Int = 0
    private var autoRefreshTask: Task<Void, Never>? = nil
    /// Last sysext bootPhase seen, to edge-detect the non-ready→ready
    /// transition that drives a one-shot live-data reconnect after the
    /// daemon (re)boots — e.g. when the launch-time `connectLiveData()`
    /// probe ran before the (re)started sysext had created its on-disk
    /// stores, leaving the dashboard on mock or a *degraded* live provider.
    private var lastBootPhase: String? = nil

    /// Refresh cadence in seconds. Aligned with v1
    /// `pollIntervalSeconds` AppStorage so toggling either side
    /// stays in sync.
    public var refreshIntervalSeconds: Int {
        max(2, UserDefaults.standard.object(forKey: "pollIntervalSeconds") as? Int ?? 5)
    }

    /// Per-workspace filter state. Workspaces read/write here so a
    /// filter survives leaving and returning to the tab.
    @Published public var alertSeverityFilter: V2Severity? = nil
    @Published public var alertSearchQuery: String = ""
    /// Time range key — "24h" / "7d" / "30d" / "all". Default 7d so
    /// the Open + History tabs match the Campaigns empty-state copy
    /// promise of "last 7 days".
    @Published public var alertTimeRange: String = "7d"
    @Published public var ruleSearchQuery: String = ""
    /// Pending IOC/threat-intel search needle. Set by the command
    /// palette's `ip:<addr>` "Search IOC matches" item (→ Intelligence ›
    /// Threat Intel) and consumed once by V2IntelligenceWorkspace, which
    /// applies it to the Threat Intel search field and clears it. Pre-fix
    /// `applyFilters` had no `.intelligence` branch and Intelligence had no
    /// query reader, so the `q` filter was silently dropped and the palette
    /// item navigated but never searched.
    @Published public var pendingIntelQuery: String? = nil
    /// Pending pre-fill for the Events workspace's FTS filter. Set by
    /// "Investigate in Events" buttons (alert / campaign inspectors)
    /// and consumed once by V2EventsWorkspace on mount, then cleared
    /// so the prefill isn't re-applied on subsequent visits.
    @Published public var pendingEventsFilter: String? = nil
    /// Pending center timestamp for the Events workspace. When set,
    /// EventStream constrains the query to a tight window around this
    /// time (default ±30 min). Used so an alert at 14:32 → Investigate
    /// → Events lands the user on events from 14:02–15:02 specifically,
    /// not "everything in the last 24h that matches the filter".
    @Published public var pendingEventsCenterTime: Date? = nil
    /// Half-window in seconds applied around `pendingEventsCenterTime`.
    /// Default 30 minutes (1800 s). Configurable so trace + campaign
    /// callers can pick a different window (e.g. campaigns are
    /// inherently broader and may want ±2h).
    @Published public var pendingEventsHalfWindowSeconds: TimeInterval = 30 * 60
    /// Pending [start, end] time-window narrowing for the Alerts Open
    /// list. Set by the Overview alert-histogram bar tap (each bar is one
    /// time bucket) so tapping "14:00–15:00" opens Alerts constrained to
    /// that hour — analogous to `pendingEventsCenterTime` for Events.
    /// Persists on state (survives the 5 s reload) until the user picks a
    /// time-range chip or clears the banner; the Alerts workspace reads it
    /// to bound its list and surfaces a dismissable banner. Pre-fix
    /// `applyFilters` had no from/to branch for `.alerts`, so the bucket
    /// window was silently dropped and the list stayed on the 7d default.
    @Published public var pendingAlertsWindow: V2TimeWindow? = nil

    // MARK: - Persistence keys

    private static let workspaceKey = "v2.dashboard.workspace"
    private static let selectedTabsKey = "v2.dashboard.selectedTabs"
    private static let recentsKey = "v2.dashboard.recents"

    private var toastDismissTask: Task<Void, Never>? = nil

    public init() {
        // Restore last workspace, else default to Overview.
        let raw = UserDefaults.standard.string(forKey: Self.workspaceKey) ?? V2Workspace.overview.rawValue
        self.currentWorkspace = V2Workspace(rawValue: raw) ?? .overview

        // Restore per-workspace tab selections.
        var tabs: [V2Workspace: V2WorkspaceTab] = [:]
        if let data = UserDefaults.standard.data(forKey: Self.selectedTabsKey),
           let dict = try? JSONDecoder().decode([String: String].self, from: data) {
            for (wkRaw, tabRaw) in dict {
                if let wk = V2Workspace(rawValue: wkRaw),
                   let tab = V2WorkspaceTab(rawValue: tabRaw),
                   tab.workspace == wk {
                    tabs[wk] = tab
                }
            }
        }
        for wk in V2Workspace.allCases where tabs[wk] == nil {
            if let def = wk.defaultTab { tabs[wk] = def }
        }
        self.selectedTabs = tabs

        // Restore recent destinations.
        if let data = UserDefaults.standard.data(forKey: Self.recentsKey),
           let urls = try? JSONDecoder().decode([String].self, from: data) {
            self.recentDestinations = urls.compactMap { URL(string: $0).flatMap(V2DeepLink.parse) }
        }

        // Seed history with the initial workspace.
        history.push(V2NavigationDestination(
            workspace: currentWorkspace,
            tab: tabs[currentWorkspace]
        ))
    }

    // MARK: - Live data

    /// Try to open the on-disk MacCrabCore stores. If any DB exists,
    /// flips `provider` to a `V2LiveDataProvider`. Idempotent — safe
    /// to call repeatedly (e.g. after the user installs the daemon).
    public func connectLiveData() async {
        if let live = await V2LiveDataProvider() {
            self.provider = live
            let dir = live.dataDir.map { " (\($0))" } ?? ""
            showToast(V2Toast(
                kind: .success,
                title: "Live data connected",
                detail: "Reading from on-disk MacCrabCore stores\(dir)"
            ))
        } else {
            showToast(V2Toast(
                kind: .info,
                title: "No daemon data found",
                detail: "Start or approve the daemon, then try again",
                displayFor: 4
            ))
        }
    }

    /// Re-probe the on-disk stores and switch to a (healthier) live provider
    /// WITHOUT the `connectLiveData()` toasts. Recovers the cases the
    /// launch-time `connectLiveData()` can miss after a sysext (re)boot:
    ///   • no DBs existed at the launch probe → still on mock once they appear;
    ///   • a store's DB was absent at the launch probe (e.g. events.db present
    ///     but alerts.db not yet created mid-(re)boot) → a *degraded* live
    ///     provider whose `alerts()` returns [] — `lastErrorDescription` is
    ///     non-nil — and the DB now opens cleanly;
    ///   • the canonical data directory changed (system ⇄ user-home).
    /// Silent on failure (keeps the current provider — e.g. a probe that lands
    /// mid-VACUUM). Note a merely *locked* DB still opens read-only, so that
    /// case is already live and needs no recovery. Swaps ONLY when the probe
    /// succeeds AND the current provider is mock, on a different dir, or
    /// degraded while the re-probe is clean — so a redundant probe to the same
    /// healthy live dir is a no-op and steady state never regresses (no thrash).
    public func reconnectLiveDataIfStale() async {
        guard let live = await V2LiveDataProvider() else { return }
        if Self.shouldAdoptReprobe(
            currentMode: provider.mode,
            currentDir: provider.dataDir,
            currentDegraded: provider.lastErrorDescription != nil,
            reprobeDir: live.dataDir,
            reprobeDegraded: live.lastErrorDescription != nil
        ) {
            self.provider = live
        }
    }

    /// Pure swap decision for `reconnectLiveDataIfStale`, extracted for unit
    /// testing. Adopt the re-probed provider when the current one is NOT a
    /// healthy live provider on the same dir: it's mock, on a different data
    /// directory, or degraded (a store failed to open) while the re-probe is
    /// clean. A healthy live provider on the same dir is a no-op — so a
    /// redundant probe never thrashes the provider or regresses steady state.
    nonisolated static func shouldAdoptReprobe(
        currentMode: V2DataSourceMode, currentDir: String?, currentDegraded: Bool,
        reprobeDir: String?, reprobeDegraded: Bool
    ) -> Bool {
        if currentMode != .live { return true }
        if currentDir != reprobeDir { return true }
        if currentDegraded && !reprobeDegraded { return true }
        return false
    }

    /// Drive a one-shot reconnect on the sysext's non-ready→ready boot
    /// edge. Called from the shell's `.onChange(of: heartbeat.bootPhase)`.
    /// Fires at most once per (re)boot: the daemon writes bootPhase="ready"
    /// once per start, and the edge guard ignores the steady stream of
    /// "ready" heartbeats that follow — so this never thrashes the provider.
    public func onSysextBootPhase(_ phase: String?) async {
        // Record the new phase BEFORE the await so an interleaving call
        // during reconnectLiveDataIfStale() sees the updated value and can't
        // double-fire the same edge.
        let fire = Self.bootPhaseDidBecomeReady(previous: lastBootPhase, next: phase)
        lastBootPhase = phase
        if fire { await reconnectLiveDataIfStale() }
    }

    /// Pure non-ready→ready edge detector for `onSysextBootPhase`, extracted
    /// for unit testing. True exactly when the sysext just reached "ready"
    /// from a non-ready (or unknown/nil) phase — so the steady stream of
    /// "ready" heartbeats that follows a boot fires the reconnect zero times.
    nonisolated static func bootPhaseDidBecomeReady(previous: String?, next: String?) -> Bool {
        previous != "ready" && next == "ready"
    }

    public func disconnectLiveData() {
        #if DEBUG
        self.provider = V2MockDataProvider()
        showToast(V2Toast(kind: .info, title: "Switched to sample data"))
        #else
        self.provider = V2OfflineDataProvider()
        showToast(V2Toast(kind: .info, title: "Disconnected from live data"))
        #endif
    }

    /// Start the periodic refresh loop. Idempotent.
    public func startAutoRefresh() {
        autoRefreshTask?.cancel()
        autoRefreshTask = Task { [weak self] in
            while !Task.isCancelled {
                let secs = await MainActor.run { self?.refreshIntervalSeconds ?? 5 }
                try? await Task.sleep(nanoseconds: UInt64(secs) * 1_000_000_000)
                guard !Task.isCancelled else { break }
                await MainActor.run { self?.refreshTick &+= 1 }
            }
        }
    }

    public func stopAutoRefresh() {
        autoRefreshTask?.cancel()
        autoRefreshTask = nil
    }

    // MARK: - Mutations

    public func goto(_ destination: V2NavigationDestination, recordHistory: Bool = true) {
        applyDestination(destination)
        if recordHistory {
            history.push(destination)
            recordRecent(destination)
        }
        paletteOpen = false
        persist()
    }

    public func goto(url: URL) {
        guard let destination = V2DeepLink.parse(url) else {
            showToast(V2Toast(kind: .error, title: "Could not open link",
                              detail: url.absoluteString))
            return
        }
        goto(destination)
    }

    public func selectTab(_ tab: V2WorkspaceTab) {
        let dest = V2NavigationDestination(workspace: tab.workspace, tab: tab)
        goto(dest)
    }

    public func switchWorkspace(_ workspace: V2Workspace) {
        guard workspace != currentWorkspace else { return }
        let dest = V2NavigationDestination(
            workspace: workspace,
            tab: selectedTabs[workspace] ?? workspace.defaultTab
        )
        goto(dest)
    }

    public func currentTab() -> V2WorkspaceTab? {
        selectedTabs[currentWorkspace] ?? currentWorkspace.defaultTab
    }

    // MARK: - Back / forward

    public func goBack() {
        guard let dest = history.back() else { return }
        applyDestination(dest)
    }

    public func goForward() {
        guard let dest = history.forward() else { return }
        applyDestination(dest)
    }


    // MARK: - Toasts

    public func showToast(_ toast: V2Toast) {
        self.toast = toast
        toastDismissTask?.cancel()
        let id = toast.id
        toastDismissTask = Task { [weak self] in
            try? await Task.sleep(nanoseconds: UInt64(toast.displayFor * 1_000_000_000))
            guard !Task.isCancelled else { return }
            await MainActor.run {
                if self?.toast?.id == id { self?.toast = nil }
            }
        }
    }

    public func dismissToast() {
        toastDismissTask?.cancel()
        toast = nil
    }

    // MARK: - Internals

    private func applyDestination(_ destination: V2NavigationDestination) {
        if currentWorkspace != destination.workspace {
            currentWorkspace = destination.workspace
        }
        if let tab = destination.tab, tab.workspace == destination.workspace {
            selectedTabs[destination.workspace] = tab
        }
        if let entityId = destination.entityId {
            let key = entityKey(workspace: destination.workspace, tab: destination.tab)
            selectedEntities[key] = entityId
        }
        applyFilters(destination.filters, in: destination.workspace, tab: destination.tab)
    }

    private func applyFilters(_ filters: [String: String], in workspace: V2Workspace, tab: V2WorkspaceTab?) {
        if workspace == .alerts {
            if let sevRaw = filters["severity"],
               let sev = V2Severity(rawValue: sevRaw) {
                alertSeverityFilter = sev
            }
            if let q = filters["q"] { alertSearchQuery = q }
            // D7: Overview alert-histogram bar tap emits epoch-second
            // "from"/"to" for the tapped bucket. Store it as a pending
            // window the Alerts workspace bounds its Open list on. Pre-fix
            // only severity/q were handled, so the window was dropped and
            // the tap looked like a plain "go to Alerts" with no narrowing.
            if let fromRaw = filters["from"], let toRaw = filters["to"],
               let from = TimeInterval(fromRaw), let to = TimeInterval(toRaw),
               to > from {
                pendingAlertsWindow = V2TimeWindow(
                    start: Date(timeIntervalSince1970: from),
                    end: Date(timeIntervalSince1970: to)
                )
            }
        }
        if workspace == .detection, tab == .detectionRules, let q = filters["q"] {
            ruleSearchQuery = q
        }
        // D8: command-palette `ip:<addr>` → "Search IOC matches" navigates
        // to Intelligence › Threat Intel with a `q` needle. Store it so the
        // Intelligence workspace pre-fills its Threat Intel search. Pre-fix
        // there was no `.intelligence` branch, so `q` was dropped and the
        // "Search IOC matches" item navigated but never actually searched.
        if workspace == .intelligence, let q = filters["q"] {
            pendingIntelQuery = q
        }
        // Modal-intent filter. The command palette's "Create Detection Rule"
        // navigates here with modal=new; V2DetectionWorkspace observes
        // presentNewRuleTick to open RuleWizard (the same path the Overview
        // "Create Rule" quick-action uses). Pre-this the filter was silently
        // dropped, so the palette navigated to Detection but no wizard opened.
        if workspace == .detection, filters["modal"] == "new" {
            presentNewRuleTick += 1
        }
    }

    private func recordRecent(_ destination: V2NavigationDestination) {
        if destination.tab == nil && destination.entityId == nil { return }
        recentDestinations.removeAll { $0 == destination }
        recentDestinations.insert(destination, at: 0)
        if recentDestinations.count > 12 {
            recentDestinations.removeLast(recentDestinations.count - 12)
        }
        persistRecents()
    }

    private func entityKey(workspace: V2Workspace, tab: V2WorkspaceTab?) -> String {
        if let tab { return "\(workspace.rawValue):\(tab.rawValue)" }
        return workspace.rawValue
    }

    private func persist() {
        UserDefaults.standard.set(currentWorkspace.rawValue, forKey: Self.workspaceKey)
        let dict: [String: String] = Dictionary(uniqueKeysWithValues:
            selectedTabs.map { ($0.key.rawValue, $0.value.rawValue) }
        )
        if let data = try? JSONEncoder().encode(dict) {
            UserDefaults.standard.set(data, forKey: Self.selectedTabsKey)
        }
    }

    private func persistRecents() {
        let urls = recentDestinations.compactMap { V2DeepLink.url(for: $0)?.absoluteString }
        if let data = try? JSONEncoder().encode(urls) {
            UserDefaults.standard.set(data, forKey: Self.recentsKey)
        }
    }
}

/// A closed [start, end] time window used for cross-workspace
/// navigation narrowing (e.g. the Overview histogram → Alerts hand-off).
public struct V2TimeWindow: Equatable, Sendable {
    public let start: Date
    public let end: Date
    public init(start: Date, end: Date) {
        self.start = start
        self.end = end
    }
}
