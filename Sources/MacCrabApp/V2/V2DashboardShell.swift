// V2DashboardShell.swift
// Top-level layout for Dashboard v2 — sidebar + top bar + workspace
// content area + global command palette overlay + toast surface.

import SwiftUI

struct V2DashboardShell: View {

    @StateObject private var state = V2DashboardState()
    @ObservedObject var appState: AppState
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @AppStorage("v2.colorScheme") private var colorSchemeRaw: String = "dark"

    init(appState: AppState) {
        self.appState = appState
    }

    private var resolvedColorScheme: ColorScheme {
        colorSchemeRaw == "light" ? .light : .dark
    }

    var body: some View {
        ZStack(alignment: .top) {
            V2Theme.canvasBackground.ignoresSafeArea()

            HStack(spacing: 0) {
                V2Sidebar(state: state, appState: appState, onProtectionTap: {
                    state.goto(V2NavigationDestination(
                        workspace: .system, tab: .systemHealth
                    ))
                })

                VStack(spacing: 0) {
                    V2CommandBar(state: state)

                    V2WorkspaceHeader(
                        title: state.currentWorkspace.title,
                        subtitle: state.currentWorkspace.subtitle
                    )

                    ZStack {
                        // Pre-fix: `.id(state.currentWorkspace)` here
                        // forced SwiftUI to dismantle the entire
                        // workspace subtree on every nav, which (a)
                        // wiped per-workspace `@State` (e.g. the
                        // TraceGraph's traceMembersCache + force-
                        // layout cachedPositions, the Investigation's
                        // selectedTrace), so every visit re-fetched +
                        // re-solved from cold; and (b) ran the new
                        // workspace's `.task(id:)` cold-fetch
                        // alongside the old workspace's still-
                        // animating render. SwiftUI's `switch` in
                        // `workspaceContent` already replaces views
                        // correctly when the case changes — the .id
                        // was redundant + actively harmful. Removing
                        // it keeps caches alive across workspace
                        // switches, eliminates the cold cascade, and
                        // shaves the dismantle time off every nav.
                        workspaceContent
                            .transition(V2Motion.workspaceTransition(reduceMotion: reduceMotion))
                    }
                    .animation(V2Motion.navigation(reduceMotion: reduceMotion),
                               value: state.currentWorkspace)
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            }

            if state.paletteOpen {
                paletteOverlay
                    .transition(V2Motion.fade)
            }

            if let toast = state.toast {
                toastLayer(toast)
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
            await state.connectLiveData()
            state.startAutoRefresh()
        }
        // Critical-alert notification "View" button posts this; we
        // navigate to the alert in the Alerts workspace + Open tab.
        .onReceive(NotificationCenter.default.publisher(for: Notification.Name("maccrab.openAlert"))) { note in
            guard let id = note.userInfo?["alertId"] as? String else { return }
            state.goto(V2NavigationDestination(
                workspace: .alerts, tab: .alertsOpen, entityId: id
            ))
        }
        // maccrab:// deep links (APPCORE-01). MacCrabApp.swift's scene
        // .onOpenURL posts the OS-delivered URL here. goto(url:) parses it
        // via V2DeepLink and navigates; unknown/malformed links surface an
        // error toast without crashing.
        .onReceive(NotificationCenter.default.publisher(for: Notification.Name("maccrab.openURL"))) { note in
            guard let url = note.userInfo?["url"] as? URL else { return }
            state.goto(url: url)
        }
    }

    @ViewBuilder
    private var workspaceContent: some View {
        switch state.currentWorkspace {
        case .overview:      V2OverviewWorkspace(state: state, appState: appState)
        case .alerts:        V2AlertsWorkspace(state: state, appState: appState)
        case .events:        V2EventsWorkspace(state: state, appState: appState)
        case .investigation: V2InvestigationWorkspace(state: state, appState: appState)
        case .forensics:     V2ForensicsWorkspace(state: state, appState: appState)
        case .detection:     V2DetectionWorkspace(state: state)
        case .prevention:    V2PreventionWorkspace(state: state)
        case .intelligence:  V2IntelligenceWorkspace(state: state)
        case .system:        V2SystemWorkspace(state: state)
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

    private func toastLayer(_ toast: V2Toast) -> some View {
        VStack {
            Spacer()
            HStack {
                Spacer()
                V2ToastView(toast: toast, onDismiss: { state.dismissToast() })
                    .transition(.move(edge: .bottom).combined(with: .opacity))
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
                Button {
                    state.switchWorkspace(wk)
                } label: { Color.clear }
                .keyboardShortcut(KeyEquivalent(Character("\(wk.keyboardIndex)")), modifiers: .command)
                .frame(width: 0, height: 0).opacity(0).accessibilityHidden(true)
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

