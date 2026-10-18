// V2DashboardShell.swift
// Top-level layout for Dashboard v2 — sidebar + top bar + workspace
// content area + global command palette overlay + toast surface.

import SwiftUI

struct V2DashboardShell: View {

    @StateObject private var state: V2DashboardState
    @StateObject private var eventQuerySession: EventQuerySession
    @StateObject private var alertsPresentation = V2AlertsPresentationModel()
    @StateObject private var detectionPresentation = V2DetectionPresentation()
    @StateObject private var tableHosts = V2TableHostCache()
    @State private var noticesExpanded = false
    @State private var refreshAppearanceID: UUID?
    @ObservedObject var appState: AppState
    @ObservedObject var sysextManager: SystemExtensionManager
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @Environment(\.controlActiveState) private var controlActiveState
    // A11y: tri-state, defaulting to "system". Pre-fix this stored only
    // "light"/"dark" and defaulted to "dark", and `resolvedColorScheme` could
    // never return nil — the SwiftUI way of saying "follow the OS" — so
    // `.preferredColorScheme` unconditionally overrode
    // NSApp.effectiveAppearance. A user who runs macOS in Light, commonly
    // because dark mode halos with astigmatism, got a dark window on every
    // fresh install with no "System" option anywhere; the only escape was an
    // icon toggle in the top bar discoverable by tooltip alone. Returning nil
    // also lets the OS's increased-contrast appearances through, which the
    // hard override was suppressing.
    @AppStorage("v2.colorScheme") private var colorSchemeRaw: String = "system"

    init(appState: AppState, sysextManager: SystemExtensionManager) {
        _state = StateObject(wrappedValue: V2DashboardState(engineSource: appState.engineSource))
        _eventQuerySession = StateObject(wrappedValue: EventQuerySession(reader: appState))
        self.appState = appState
        self.sysextManager = sysextManager
    }

    private var resolvedColorScheme: ColorScheme? {
        switch colorSchemeRaw {
        case "light": return .light
        case "dark":  return .dark
        default:      return nil   // follow the system appearance
        }
    }

    private var rulesTableIdentity: V2DetectionPresentation.Identity {
        .init(provider: ObjectIdentifier(state.provider), directory: state.engineSource.directory,
              epoch: appState.eventQueryEpoch)
    }

    private var alertsTableContext: V2AlertsPresentationContext {
        .init(query: .init(providerID: ObjectIdentifier(state.provider), timeRange: state.alertTimeRange,
                           windowStart: state.pendingAlertsWindow?.start,
                           windowEnd: state.pendingAlertsWindow?.end),
              directory: state.provider.dataDir,
              engine: appState.heartbeat?.engineIdentity.map(V2AlertsPresentationContext.Engine.init))
    }

    var body: some View {
        ZStack(alignment: .top) {
            V2Theme.canvasBackground.ignoresSafeArea()

            V2SidebarContentLayout(sidebar: { availableWidth in
                V2Sidebar(state: state, appState: appState, availableWidth: availableWidth, onProtectionTap: {
                    state.goto(V2NavigationDestination(
                        workspace: .system, tab: .systemHealth
                    ))
                })
            }, content: {
                VStack(spacing: 0) {
                    V2CommandBar(state: state)

                    V2WorkspaceHeader(
                        title: state.currentWorkspace.title,
                        subtitle: state.currentWorkspace.subtitle
                    )

                    ZStack {
                        // Identity follows the conditional workspace tree;
                        // do not add a redundant .id(currentWorkspace).
                        // Switching cases can still recreate view-local
                        // @State. Bounded presentation models belong to this
                        // window; hidden workspaces do not retain page views or
                        // poll. Only two bounded, detached pure tables may be
                        // reused; their old bindings/actions are revoked.
                        // An already-owned Events verification may finish
                        // within its deadline under Core's normal read lifecycle.
                        workspaceContent
                            .transition(.identity)
                    }
                    // Swap the page immediately instead of cross-fading two
                    // data-heavy trees. Only workspace changes clear this
                    // animation; inspector, palette and toast motion stay local.
                    .animation(nil, value: state.currentWorkspace)
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            })

            if state.paletteOpen {
                paletteOverlay
                    .transition(V2Motion.fade)
            }

            if state.toast != nil || !state.noticeHistory.isEmpty {
                toastLayer
                    .transition(V2Motion.toastTransition(reduceMotion: reduceMotion))
            }
        }
        .preferredColorScheme(resolvedColorScheme)
        // Window-minimum sizing lives on the WindowGroup's V2RootView
        // (see MacCrabApp.swift). A second `.frame(minWidth:)` here used
        // to force the HStack to lay out at 1280pt regardless of the
        // actual window size, pushing the top bar's trailing icon
        // buttons past the right edge when the window was dragged
        // narrower than 1280. Removed in v1.12.9.
        .background(workspaceShortcutHandlers)
        .animation(V2Motion.overlay(reduceMotion: reduceMotion), value: state.paletteOpen)
        .animation(V2Motion.toast(reduceMotion: reduceMotion), value: state.toast?.id)
        .task {
            // Best-effort live data connect + start auto-refresh on
            // first launch. No-op for live if no MacCrab DBs exist.
            guard !Task.isCancelled else { return }
            let appearanceID = UUID()
            refreshAppearanceID = appearanceID
            // A restored window can appear while another app is active, before
            // any activity change notification arrives.
            state.setWindowActivity(controlActiveState)
            state.beginInitialVisitTiming(epoch: appState.eventQueryEpoch, deferred: appState.eventReadsDeferred)
            if controlActiveState == .inactive { eventQuerySession.cancelBackendReads() }
            else { eventQuerySession.resumeBackendReads() }
            await state.connectLiveData()
            guard !Task.isCancelled, refreshAppearanceID == appearanceID else { return }
            state.startAutoRefresh()
        }
        .onDisappear {
            // Invalidate an in-flight connect even before SwiftUI delivers task
            // cancellation; an older appearance cannot restart this window.
            refreshAppearanceID = nil
            state.stopVisitTiming(.windowClosed)
            tableHosts.removeAll()
            eventQuerySession.cancelBackendReads()
            state.stopAutoRefresh()
        }
        // Upgrade-handoff recovery: when the sysext finishes (re)booting
        // (bootPhase non-ready→ready), re-probe the on-disk stores once.
        // Covers the case where the launch-time connectLiveData() probe ran
        // before the (re)started sysext had created its DBs — leaving the
        // dashboard on mock or a degraded live provider (a store's DB absent
        // at probe time) until a manual restart. Edge-gated in the state, so
        // a steady stream of "ready" heartbeats triggers nothing.
        .onChange(of: appState.heartbeat?.engineIdentity) { identity in
            tableHosts.evictDetached(disqualifyActive: false)
            eventQuerySession.reconcileBackendContext()
            Task { await state.onEngineIdentity(identity) }
        }
        .onChange(of: appState.eventQueryEpoch) { _ in
            state.reconcileVisitTimingBackend(epoch: appState.eventQueryEpoch, deferred: appState.eventReadsDeferred)
            tableHosts.evictDetached(disqualifyActive: false)
            eventQuerySession.reconcileBackendContext()
        }
        .onChange(of: state.visitTimingContext) { _ in state.reconcileVisitTimingContext() }
        .onChange(of: rulesTableIdentity) { _ in tableHosts.evictDetached(slot: .rules, disqualifyActive: false) }
        .onChange(of: alertsTableContext) { _ in tableHosts.evictDetached(slot: .openAlerts, disqualifyActive: false) }
        .onChange(of: state.ruleSearchQuery) { _ in tableHosts.evictDetached(slot: .rules, disqualifyActive: false) }
        .onChange(of: state.alertSearchQuery) { _ in tableHosts.evictDetached(slot: .openAlerts, disqualifyActive: false) }
        .onChange(of: state.alertSeverityFilter) { _ in tableHosts.evictDetached(slot: .openAlerts, disqualifyActive: false) }
        .onChange(of: detectionPresentation.revision) { _ in tableHosts.evictDetached(slot: .rules, disqualifyActive: false) }
        .onChange(of: alertsPresentation.rows) { _ in tableHosts.evictDetached(slot: .openAlerts, disqualifyActive: false) }
        .onChange(of: detectionPresentation.canRetainTable(for: rulesTableIdentity)) { allowed in
            if !allowed { tableHosts.evictDetached(slot: .rules, disqualifyActive: false) }
        }
        .onChange(of: alertsPresentation.canRetainTable(for: alertsTableContext)) { allowed in
            if !allowed { tableHosts.evictDetached(slot: .openAlerts, disqualifyActive: false) }
        }
        .onChange(of: appState.eventReadsDeferred) { _ in
            state.reconcileVisitTimingBackend(epoch: appState.eventQueryEpoch, deferred: appState.eventReadsDeferred)
            eventQuerySession.reconcileBackendContext()
        }
        .onChange(of: appState.heartbeat?.bootPhase) { newPhase in
            Task { await state.onSysextBootPhase(newPhase) }
        }
        // LSUIElement scenePhase can remain active after the window loses
        // activity. Use the same window signal as the mascot to pause this
        // dashboard's refreshes; global health/notification polling is separate.
        // On return, re-probe only a missing or failed provider.
        .onChange(of: controlActiveState) { activity in
            let becameActive = state.setWindowActivity(activity)
            if activity == .inactive {
                tableHosts.evictDetached()
                eventQuerySession.cancelBackendReads()
                alertsPresentation.pause()
                detectionPresentation.leave()
            } else {
                eventQuerySession.resumeBackendReads()
            }
            guard becameActive,
                  state.provider.mode != .live || state.provider.lastErrorDescription != nil
            else { return }
            Task { await state.reconnectLiveDataIfStale() }
        }
        // Critical-alert notification "View" button posts this; we
        // navigate to the alert in the Alerts workspace + Open tab.
        .onReceive(NotificationCenter.default.publisher(for: Notification.Name("maccrab.openAlert"))) { note in
            guard let id = note.userInfo?["alertId"] as? String else { return }
            state.goto(V2NavigationDestination(
                workspace: .alerts, tab: .alertsOpen, entityId: id
            ))
        }
        // SwiftUI delivers the URL to one selected scene. Keep its navigation
        // local, leaving other windows' investigation state untouched.
        .onOpenURL { url in
            Self.handleSceneURL(url, state: state)
        }
    }

    @MainActor
    static func handleSceneURL(_ url: URL, state: V2DashboardState) {
        // The enclosing app view owns these existing confirmation flows.
        guard url.host != "deactivate", url.host != "install" else { return }
        state.goto(url: url)
    }

    @ViewBuilder
    private var workspaceContent: some View {
        switch state.currentWorkspace {
        case .overview:      V2OverviewWorkspace(state: state, appState: appState)
        case .alerts:        V2AlertsWorkspace(state: state, appState: appState, presentation: alertsPresentation,
                                               tableHosts: tableHosts)
        case .events:        V2EventsWorkspace(state: state, appState: appState, querySession: eventQuerySession)
        case .investigation: V2InvestigationWorkspace(state: state, appState: appState)
        case .forensics:     V2ForensicsWorkspace(state: state, appState: appState)
        case .detection:     V2DetectionWorkspace(state: state, appState: appState, presentation: detectionPresentation,
                                                  tableHosts: tableHosts)
        case .prevention:    V2PreventionWorkspace(state: state)
        case .intelligence:  V2IntelligenceWorkspace(state: state)
        case .system:        V2SystemWorkspace(state: state, sysextManager: sysextManager)
        case .docs:          V2DocsWorkspace(state: state)
        }
    }

    private var paletteOverlay: some View {
        ZStack {
            Color.black.opacity(0.35)
                .ignoresSafeArea()
                .onTapGesture { state.paletteOpen = false }
            V2CommandPalette(state: state)
                .padding(.top, 100)
        }
        .transition(.opacity)
        .zIndex(10)
    }

    private var toastLayer: some View {
        VStack {
            Spacer()
            HStack {
                Spacer()
                VStack(alignment: .trailing, spacing: 8) {
                    if !state.noticeHistory.isEmpty {
                        Button(String(localized: "notices.earlier", defaultValue: "Earlier notices (\(state.noticeHistory.count))")) {
                            noticesExpanded.toggle()
                        }
                        .buttonStyle(.bordered)
                        .popover(isPresented: $noticesExpanded, arrowEdge: .top) {
                            ScrollView {
                                VStack(spacing: 10) {
                                    ForEach(state.noticeHistory.reversed()) { notice in
                                        V2ToastView(toast: notice, onDismiss: { state.dismissToast(id: notice.id) })
                                    }
                                }.padding(12)
                            }
                            .frame(width: 390, height: 420)
                        }
                    }
                    if let toast = state.toast {
                        V2ToastView(toast: toast, onDismiss: { state.dismissToast(id: toast.id) })
                            .transition(V2Motion.toastTransition(reduceMotion: reduceMotion))
                    }
                }
                .padding(20)
            }
        }
        .zIndex(20)
        .allowsHitTesting(true)
    }

    /// Hidden buttons providing the global keyboard shortcuts.
    @ViewBuilder
    private var workspaceShortcutHandlers: some View {
        ZStack {
            ForEach(V2Workspace.allCases) { wk in
                // Only single-digit indices (1–9) are valid ⌘ shortcuts.
                // keyboardIndex 10 (Docs) would build KeyEquivalent(Character("10")),
                // a two-grapheme string that traps Character.init — so skip it.
                if wk.keyboardIndex <= 9 {
                    Button {
                        state.switchWorkspace(wk)
                    } label: { Color.clear }
                    .keyboardShortcut(KeyEquivalent(Character("\(wk.keyboardIndex)")), modifiers: .command)
                    .frame(width: 0, height: 0).opacity(0).accessibilityHidden(true)
                }
            }

            Button { state.paletteOpen.toggle() } label: { Color.clear }
                .keyboardShortcut("p", modifiers: [.command, .shift])
                .frame(width: 0, height: 0).opacity(0).accessibilityHidden(true)

            Button { state.paletteOpen.toggle() } label: { Color.clear }
                .keyboardShortcut("k", modifiers: .command)
                .frame(width: 0, height: 0).opacity(0).accessibilityHidden(true)

            // ⌘, opens the real v1 Settings window. The v2
            // System › Settings tab is preview-only.
            Button {
                V2SettingsBridge.openSettings()
            } label: { Color.clear }
                .keyboardShortcut(",", modifiers: .command)
                .frame(width: 0, height: 0).opacity(0).accessibilityHidden(true)

            Button {
                if state.paletteOpen { state.paletteOpen = false }
                else if state.toast != nil { state.dismissToast() }
            } label: { Color.clear }
                .keyboardShortcut(.escape, modifiers: [])
                .frame(width: 0, height: 0).opacity(0).accessibilityHidden(true)

            // ⌘[ / ⌘] for back / forward
            Button { state.goBack() } label: { Color.clear }
                .keyboardShortcut("[", modifiers: .command)
                .frame(width: 0, height: 0).opacity(0).accessibilityHidden(true)
            Button { state.goForward() } label: { Color.clear }
                .keyboardShortcut("]", modifiers: .command)
                .frame(width: 0, height: 0).opacity(0).accessibilityHidden(true)
        }
        .frame(width: 0, height: 0)
    }
}
