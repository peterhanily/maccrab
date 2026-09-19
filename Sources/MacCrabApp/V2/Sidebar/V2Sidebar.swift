// V2Sidebar.swift
// Left sidebar — full-row click targets, hover state, brand-tinted
// active row (Mac-style accent), collapsible to icon-only width,
// and a drag handle on the right edge for live resizing.

import SwiftUI
import AppKit
import MacCrabCore

struct V2Sidebar: View {

    @ObservedObject var state: V2DashboardState
    @ObservedObject var appState: AppState
    let onProtectionTap: () -> Void

    @AppStorage("v2.sidebar.width")     private var storedWidth: Double = 220
    @AppStorage("v2.sidebar.collapsed") private var collapsed: Bool = false
    // Density toggle (Settings › Appearance). Gates which workspaces show in the
    // sidebar; defaults to .advanced so upgrades keep the full surface.
    @AppStorage(UIMode.storageKey)      private var uiModeRaw: String = UIMode.advanced.rawValue
    private var currentUIMode: UIMode { UIMode(rawValue: uiModeRaw) ?? .advanced }

    private let collapsedWidth: CGFloat = 56
    private let minWidth: CGFloat = 180
    private let maxWidth: CGFloat = 360

    init(state: V2DashboardState, appState: AppState, onProtectionTap: @escaping () -> Void) {
        self.state = state
        self.appState = appState
        self.onProtectionTap = onProtectionTap
    }

    private var resolvedWidth: CGFloat {
        collapsed ? collapsedWidth : CGFloat(min(max(storedWidth, minWidth), maxWidth))
    }

    public var body: some View {
        ZStack(alignment: .trailing) {
            VStack(alignment: .leading, spacing: 0) {
                brandHeader
                    .padding(.horizontal, collapsed ? 8 : 12)
                    .padding(.top, 12)
                    .padding(.bottom, 12)

                // v1.11.1 (audit UX MEDIUM): visual subgrouping to
                // reduce sidebar clutter. The 9 workspaces split
                // naturally into 4 task buckets — Monitor (where the
                // user lives day-to-day), Investigate (when something
                // looks off), Configure (the rule engine + prevention),
                // and System (operational concerns + docs). Group
                // labels only render when the sidebar is expanded;
                // collapsed mode shows icons only without headers.
                // This is the lighter version of the v1.11.x sidebar
                // consolidation proposal (`plans/2026-05-07-dashboard-
                // overhaul.md`) — that one collapses to 7 workspaces;
                // v1.11.1 keeps the surface stable and just adds
                // grouping. Same surface, less visual noise.
                VStack(spacing: 2) {
                    ForEach(V2SidebarGroup.allCases) { group in
                        // Always surface the ACTIVE workspace even when the
                        // current density mode would hide it. ⌘N / the command
                        // palette / deep links can navigate to a workspace below
                        // the current density (visibility gates the sidebar, not
                        // navigation) — without this the workspace would render
                        // with no matching sidebar row, leaving the nav with no
                        // active selection. Surfacing it (highlighted, since it's
                        // active) keeps the sidebar and the content in agreement.
                        let visible = group.workspaces.filter {
                            $0.isVisible(in: currentUIMode) || $0 == state.currentWorkspace
                        }
                        // Header only when the group has at least one visible
                        // workspace in this density mode (no empty section labels).
                        if !collapsed, !visible.isEmpty, let label = group.headerLabel {
                            Text(label)
                                .scaledSystem(10, weight: .semibold)
                                .foregroundStyle(V2Theme.tertiaryText)
                                .textCase(.uppercase)
                                .padding(.horizontal, 12)
                                .padding(.top, group == .monitor ? 0 : 12)
                                .padding(.bottom, 4)
                                .frame(maxWidth: .infinity, alignment: .leading)
                                .accessibilityAddTraits(.isHeader)
                        }
                        ForEach(visible) { workspace in
                            V2SidebarItem(
                                workspace: workspace,
                                isActive: state.currentWorkspace == workspace,
                                collapsed: collapsed,
                                onSelect: { state.switchWorkspace(workspace) }
                            )
                        }
                    }
                }
                // Nav safety: if the density mode changes while the user is on a
                // now-hidden workspace, fall back to Overview so the sidebar and
                // the displayed workspace don't disagree. (The workspace is still
                // reachable via the command palette.)
                .onChange(of: uiModeRaw) { _ in
                    if !state.currentWorkspace.isVisible(in: currentUIMode) {
                        state.switchWorkspace(.overview)
                    }
                }
                .padding(.horizontal, collapsed ? 6 : 8)

                Spacer(minLength: 0)

                // UX-04: Basic shows 4 of 10 workspaces and Standard 8, and the
                // sidebar drops the rest silently — a user told (by the Welcome
                // checklist, the docs, or a colleague) to open Prevention or
                // Detection has no in-app signal that those exist, let alone that
                // ⌘K reaches them. One row, rendered only when something is
                // actually hidden.
                hiddenWorkspacesRow
                    .padding(.horizontal, collapsed ? 6 : 8)
                    .padding(.bottom, 6)

                protectionFooter
                    .padding(.horizontal, collapsed ? 6 : 8)
                    .padding(.bottom, 8)
            }
            .frame(width: resolvedWidth)
            .frame(maxHeight: .infinity)
            .background(V2Theme.sidebarBackground)
            .overlay(
                Rectangle().fill(V2Theme.panelBorder).frame(width: 1),
                alignment: .trailing
            )

            // Right-edge drag handle (resize). 6px hit zone, invisible.
            if !collapsed {
                resizeHandle
            }
        }
        .frame(width: resolvedWidth)
    }

    // MARK: - Hidden-workspace affordance

    /// Workspaces the current density mode hides. The active workspace is
    /// always surfaced in the list above (see the `visible` filter), so it is
    /// never counted as hidden.
    private var hiddenWorkspaceCount: Int {
        V2Workspace.allCases.filter {
            !$0.isVisible(in: currentUIMode) && $0 != state.currentWorkspace
        }.count
    }

    @ViewBuilder
    private var hiddenWorkspacesRow: some View {
        if hiddenWorkspaceCount > 0 {
            Button { state.paletteOpen = true } label: {
                HStack(spacing: 10) {
                    Image(systemName: "ellipsis.circle")
                        .scaledSystem(14, weight: .medium)
                        .foregroundStyle(V2Theme.tertiaryText)
                        .frame(width: 18, alignment: .center)
                    if !collapsed {
                        Text(String(localized: "sidebar.moreWorkspaces",
                                    defaultValue: "\(hiddenWorkspaceCount) more workspaces"))
                            .scaledSystem(12)
                            .foregroundStyle(V2Theme.tertiaryText)
                        Spacer(minLength: 0)
                        Text(verbatim: "⌘K")
                            .scaledSystem(11)
                            .foregroundStyle(V2Theme.tertiaryText)
                    }
                }
                .padding(.horizontal, collapsed ? 6 : 10)
                .padding(.vertical, 6)
                .frame(maxWidth: .infinity, alignment: collapsed ? .center : .leading)
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .help(String(localized: "sidebar.moreWorkspacesHelp",
                         defaultValue: "Open the command palette to reach workspaces hidden by the current display mode"))
            .accessibilityLabel(String(localized: "sidebar.ax.moreWorkspaces",
                                       defaultValue: "\(hiddenWorkspaceCount) more workspaces. Opens the command palette."))
        }
    }

    // MARK: - Resize handle

    private var resizeHandle: some View {
        Rectangle()
            .fill(Color.clear)
            .frame(width: 6)
            .contentShape(Rectangle())
            .onHover { hovering in
                if hovering { NSCursor.resizeLeftRight.push() }
                else        { NSCursor.pop() }
            }
            .gesture(
                DragGesture()
                    .onChanged { value in
                        let new = CGFloat(storedWidth) + value.translation.width
                        storedWidth = Double(min(max(new, minWidth), maxWidth))
                    }
            )
            // v1.18.1: the drag-only handle was invisible to VoiceOver and
            // unreachable by keyboard. Expose it as an adjustable element —
            // VO increment/decrement nudges the width 20 pt per step.
            .accessibilityElement()
            .accessibilityLabel(String(localized: "sidebar.ax.resize",
                                       defaultValue: "Sidebar width"))
            .accessibilityValue("\(Int(storedWidth))")
            .accessibilityAdjustableAction { direction in
                let step: Double = direction == .increment ? 20 : -20
                storedWidth = Double(min(max(CGFloat(storedWidth + step), minWidth), maxWidth))
            }
    }

    // MARK: - Header

    private var brandHeader: some View {
        // When collapsed: vertical stack so the collapse button
        // doesn't overflow the 56px sidebar width.
        Group {
            if collapsed {
                VStack(spacing: 8) {
                    Text("🦀")
                        .scaledSystem(22)
                        .frame(width: 36, height: 36)
                        .background(V2Theme.brand.opacity(0.15))
                        .overlay(
                            RoundedRectangle(cornerRadius: 9)
                                .stroke(V2Theme.brand.opacity(0.45), lineWidth: 1)
                        )
                        .clipShape(RoundedRectangle(cornerRadius: 9))
                    collapseButton
                }
                .frame(maxWidth: .infinity, alignment: .center)
            } else {
                HStack(spacing: 10) {
                    Text("🦀")
                        .scaledSystem(24)
                        .frame(width: 36, height: 36)
                        .background(V2Theme.brand.opacity(0.15))
                        .overlay(
                            RoundedRectangle(cornerRadius: 9)
                                .stroke(V2Theme.brand.opacity(0.45), lineWidth: 1)
                        )
                        .clipShape(RoundedRectangle(cornerRadius: 9))

                    VStack(alignment: .leading, spacing: 1) {
                        Text(verbatim: "MacCrab")
                            .scaledSystem(16, weight: .bold)
                            .foregroundStyle(V2Theme.primaryText)
                        Text(verbatim: "v\(MacCrabVersion.current)")
                            .scaledSystem(11)
                            .foregroundStyle(V2Theme.tertiaryText)
                    }
                    Spacer(minLength: 0)
                    collapseButton
                }
            }
        }
    }

    private var collapseButton: some View {
        Button {
            collapsed.toggle()
        } label: {
            Image(systemName: collapsed ? "sidebar.right" : "sidebar.left")
                .scaledSystem(12, weight: .medium)
                .foregroundStyle(V2Theme.mutedText)
                .frame(width: 26, height: 26)
                .background(V2Theme.hoverBackground)
                .clipShape(RoundedRectangle(cornerRadius: 6))
                .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .help(collapsed ? "Expand sidebar" : "Collapse sidebar")
        .accessibilityLabel(collapsed ? "Expand sidebar" : "Collapse sidebar")
    }

    // MARK: - Footer

    var protectionStatus: V2ProtectionStatus {
        V2ProtectionStatus.resolve(
            providerLive: state.provider.mode == .live,
            heartbeatPresent: appState.heartbeat != nil,
            heartbeatStale: appState.heartbeat?.isStale ?? true,
            readiness: appState.heartbeat?.readiness ?? .unavailable,
            degraded: appState.isProtectionDegraded
        )
    }

    /// Match Overview's readiness even when startup defers the database provider.
    private var protectionFooter: some View {
        let status = protectionStatus
        let color: Color = status == .active ? V2Theme.healthy
            : (status == .inactive ? V2Theme.high : V2Theme.warning)
        let title: String = {
            switch status {
            case .active: return "Protection active"
            case .starting: return appState.heartbeat?.bootPhase == "upgrading_store"
                ? V2StoreUpgradeProgress.title : "Protection starting"
            case .unavailable: return "Protection unavailable"
            case .degraded: return "Protection degraded"
            case .inactive: return "Protection inactive"
            }
        }()
        let subtitle = status == .inactive ? "No daemon detected" : "Click for details"
        return Button(action: onProtectionTap) {
            HStack(spacing: 10) {
                ZStack {
                    Circle()
                        .fill(color.opacity(0.18))
                    Circle()
                        .fill(color)
                        .frame(width: 8, height: 8)
                }
                .frame(width: 28, height: 28)

                if !collapsed {
                    VStack(alignment: .leading, spacing: 1) {
                        Text(title)
                            .scaledSystem(13, weight: .semibold)
                            .foregroundStyle(V2Theme.primaryText)
                        Text(subtitle)
                            .scaledSystem(11)
                            .foregroundStyle(color)
                    }
                    Spacer(minLength: 0)
                    Image(systemName: "chevron.forward")
                        .scaledSystem(11, weight: .semibold)
                        .foregroundStyle(V2Theme.tertiaryText)
                }
            }
            .padding(.horizontal, collapsed ? 6 : 12)
            .padding(.vertical, 10)
            .frame(maxWidth: .infinity, alignment: collapsed ? .center : .leading)
            .background(V2Theme.panelBackground)
            .overlay(
                RoundedRectangle(cornerRadius: V2Theme.smallCornerRadius)
                    .stroke(V2Theme.panelBorder, lineWidth: 1)
            )
            .clipShape(RoundedRectangle(cornerRadius: V2Theme.smallCornerRadius))
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .help(String(localized: "ui.V2Sidebar.maccrab.protection.click.to.open.system.health", defaultValue: "MacCrab protection · click to open System health"))
        // v1.10.2 (audit UX HIGH): a11y label was hardcoded "active"
        // regardless of degraded/inactive state. VoiceOver users heard
        // "active" even when the daemon was offline. Use the same
        // resolved title the visible row uses.
        .accessibilityLabel("\(title). Click to open System health.")
    }
}

// MARK: - Sidebar groups (v1.11.1)
//
// Workspaces are split into 4 task buckets. Each bucket renders as
// a small uppercase header above its members when the sidebar is
// expanded. Order matters: Monitor first because it's where the
// user lives day-to-day; System last because it's accessed least.

private enum V2SidebarGroup: String, CaseIterable, Identifiable {
    case monitor, investigate, configure, system

    var id: String { rawValue }

    /// Rendered above the group's first workspace. Nil for the
    /// leading group (Monitor) so the sidebar doesn't open with a
    /// bare header. v1.11.0 RC2 ship-blocker fix: localized via
    /// `String(localized:)` so non-English bundles don't show
    /// English headers above translated workspace titles.
    var headerLabel: String? {
        switch self {
        case .monitor:     return nil
        case .investigate: return String(localized: "sidebar.group.investigate", defaultValue: "Investigate")
        case .configure:   return String(localized: "sidebar.group.configure",   defaultValue: "Configure")
        case .system:      return String(localized: "sidebar.group.system",      defaultValue: "System")
        }
    }

    var workspaces: [V2Workspace] {
        switch self {
        case .monitor:     return [.overview, .alerts]
        case .investigate: return [.events, .investigation, .forensics]
        case .configure:   return [.detection, .prevention, .intelligence]
        case .system:      return [.system, .docs]
        }
    }
}

private struct V2SidebarItem: View {
    let workspace: V2Workspace
    let isActive: Bool
    let collapsed: Bool
    let onSelect: () -> Void
    @State private var isHovering: Bool = false

    var body: some View {
        Button(action: onSelect) {
            HStack(spacing: 10) {
                Image(systemName: workspace.systemImage)
                    .scaledSystem(14, weight: .medium)
                    .foregroundStyle(iconColor)
                    .frame(width: 18, alignment: .center)

                if !collapsed {
                    Text(workspace.title)
                        .scaledSystem(13.5, weight: isActive ? .semibold : .medium)
                        .foregroundStyle(textColor)
                    Spacer(minLength: 0)
                    // Only 1–9 are real ⌘ shortcuts (see V2DashboardShell); don't
                    // advertise "⌘10" for Docs — it has no keyboard shortcut.
                    if workspace.keyboardIndex <= 9 {
                        Text("⌘\(workspace.keyboardIndex)")
                            .scaledSystem(11)
                            .foregroundStyle(isActive ? V2Theme.mutedText : V2Theme.tertiaryText)
                            .monospacedDigit()
                    }
                }
            }
            .padding(.horizontal, collapsed ? 6 : 10)
            .padding(.vertical, 7)
            .frame(maxWidth: .infinity, alignment: collapsed ? .center : .leading)
            .background(rowBackground)
            .overlay(
                RoundedRectangle(cornerRadius: 7)
                    .stroke(isActive ? V2Theme.brand.opacity(0.35) : .clear, lineWidth: 1)
            )
            .clipShape(RoundedRectangle(cornerRadius: 7))
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .onHover { isHovering = $0 }
        .help(collapsed ? workspace.title + (workspace.keyboardIndex <= 9 ? "  ⌘\(workspace.keyboardIndex)" : "") : "")
        .accessibilityAddTraits(isActive ? [.isSelected] : [])
        .accessibilityLabel(String(localized: "sidebar.ax.workspace",
                                   defaultValue: "\(workspace.title) workspace"))
        .accessibilityHint(workspace.keyboardIndex <= 9
                           ? String(localized: "sidebar.ax.workspaceHint",
                                    defaultValue: "Command \(workspace.keyboardIndex)")
                           : "")
        // v1.21.5 (UI-test harness): stable XCUITest id per workspace row —
        // AlertsFlowUITest navigates via app.buttons["sidebar.item.alerts"].
        .v2AXID("sidebar.item.\(workspace.rawValue)")
    }

    // Mac-style accent on the active row: brand-tinted bg + brand
    // icon, with a subtle border lift. Hover gets a faint overlay.
    private var iconColor: Color {
        if isActive   { return V2Theme.brand }
        if isHovering { return V2Theme.primaryText }
        return V2Theme.mutedText
    }
    private var textColor: Color {
        isActive ? V2Theme.primaryText : (isHovering ? V2Theme.primaryText : V2Theme.neutral)
    }
    private var rowBackground: Color {
        if isActive   { return V2Theme.brand.opacity(0.13) }
        if isHovering { return V2Theme.hoverBackground }
        return .clear
    }
}
