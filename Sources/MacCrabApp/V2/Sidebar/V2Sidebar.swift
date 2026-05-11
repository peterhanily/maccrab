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

                VStack(spacing: 2) {
                    ForEach(V2Workspace.allCases) { workspace in
                        V2SidebarItem(
                            workspace: workspace,
                            isActive: state.currentWorkspace == workspace,
                            collapsed: collapsed,
                            onSelect: { state.switchWorkspace(workspace) }
                        )
                    }
                }
                .padding(.horizontal, collapsed ? 6 : 8)

                Spacer(minLength: 0)

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
    }

    // MARK: - Header

    private var brandHeader: some View {
        // When collapsed: vertical stack so the collapse button
        // doesn't overflow the 56px sidebar width.
        Group {
            if collapsed {
                VStack(spacing: 8) {
                    Text("🦀")
                        .font(.system(size: 22))
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
                        .font(.system(size: 24))
                        .frame(width: 36, height: 36)
                        .background(V2Theme.brand.opacity(0.15))
                        .overlay(
                            RoundedRectangle(cornerRadius: 9)
                                .stroke(V2Theme.brand.opacity(0.45), lineWidth: 1)
                        )
                        .clipShape(RoundedRectangle(cornerRadius: 9))

                    VStack(alignment: .leading, spacing: 1) {
                        Text("MacCrab")
                            .font(.system(size: 16, weight: .bold))
                            .foregroundStyle(V2Theme.primaryText)
                        Text("v\(MacCrabVersion.current)")
                            .font(.system(size: 11))
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
                .font(.system(size: 12, weight: .medium))
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

    /// Sidebar footer reflects real protection state (active / degraded
    /// / inactive). Pre-fix it always said "Protection active" — even
    /// when the daemon was offline.
    private var protectionFooter: some View {
        let degraded = appState.isProtectionDegraded
        let inactive = state.provider.mode == .mock
        let color: Color = inactive ? V2Theme.high : (degraded ? V2Theme.warning : V2Theme.healthy)
        let title: String = inactive ? "Protection inactive" : (degraded ? "Protection degraded" : "Protection active")
        let subtitle: String = inactive ? "No daemon detected" : (degraded ? "Click for details" : "Click for details")
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
                            .font(.system(size: 13, weight: .semibold))
                            .foregroundStyle(V2Theme.primaryText)
                        Text(subtitle)
                            .font(.system(size: 11))
                            .foregroundStyle(color)
                    }
                    Spacer(minLength: 0)
                    Image(systemName: "chevron.forward")
                        .font(.system(size: 11, weight: .semibold))
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
        .help("MacCrab protection · click to open System health")
        .accessibilityLabel("MacCrab protection active. Click to open System health.")
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
                    .font(.system(size: 14, weight: .medium))
                    .foregroundStyle(iconColor)
                    .frame(width: 18, alignment: .center)

                if !collapsed {
                    Text(workspace.title)
                        .font(.system(size: 13.5, weight: isActive ? .semibold : .medium))
                        .foregroundStyle(textColor)
                    Spacer(minLength: 0)
                    Text("⌘\(workspace.keyboardIndex)")
                        .font(.system(size: 11))
                        .foregroundStyle(isActive ? V2Theme.mutedText : V2Theme.tertiaryText)
                        .monospacedDigit()
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
        .help(collapsed ? workspace.title + "  ⌘\(workspace.keyboardIndex)" : "")
        .accessibilityAddTraits(isActive ? [.isSelected] : [])
        .accessibilityLabel("\(workspace.title) workspace, ⌘\(workspace.keyboardIndex)")
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


