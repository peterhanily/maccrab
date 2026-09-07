// V2CommandBar.swift
// Top command bar with back/forward + breadcrumb + universal
// search trigger + global controls. Per spec §3.4 + page-2.

import SwiftUI

public struct V2CommandBar: View {

    @ObservedObject var state: V2DashboardState
    // Tri-state, matching V2DashboardShell. Pre-fix this was a two-state flip
    // with no way back to the OS appearance once touched — and it defaulted to
    // "dark", which is what forced a dark window on Light-mode users.
    @AppStorage("v2.colorScheme") private var colorSchemeRaw: String = "system"

    public init(state: V2DashboardState) {
        self.state = state
    }

    private var schemeIcon: String {
        switch colorSchemeRaw {
        case "light": return "sun.max.fill"
        case "dark":  return "moon.fill"
        default:      return "circle.lefthalf.filled"
        }
    }
    private var schemeName: String {
        switch colorSchemeRaw {
        case "light": return String(localized: "ax.appearance.light", defaultValue: "Light")
        case "dark":  return String(localized: "ax.appearance.dark", defaultValue: "Dark")
        default:      return String(localized: "ax.appearance.system", defaultValue: "System")
        }
    }
    // IconButton pipes `tooltip` into BOTH .help and .accessibilityLabel, so
    // naming the current state here is what gives VoiceOver the value — the
    // old text ("Switch to dark theme") announced the destination, never the
    // state, which is unusable on a control that now has three positions.
    private var schemeTooltip: String {
        String(localized: "ax.appearance.tooltip", defaultValue: "Appearance: \(schemeName) — click to change")
    }
    private func toggleScheme() {
        switch colorSchemeRaw {
        case "system": colorSchemeRaw = "light"
        case "light":  colorSchemeRaw = "dark"
        default:       colorSchemeRaw = "system"
        }
    }

    public var body: some View {
        HStack(spacing: 12) {
            HStack(spacing: 4) {
                navButton(icon: "chevron.backward",
                          enabled: state.history.canGoBack,
                          tooltip: "Back  ⌘[") { state.goBack() }
                navButton(icon: "chevron.forward",
                          enabled: state.history.canGoForward,
                          tooltip: "Forward  ⌘]") { state.goForward() }
            }

            HStack(spacing: 4) {
                breadcrumbButton(
                    icon: state.currentWorkspace.systemImage,
                    label: state.currentWorkspace.title,
                    tooltip: "Jump to \(state.currentWorkspace.title) home"
                ) {
                    if let def = state.currentWorkspace.defaultTab {
                        state.goto(V2NavigationDestination(
                            workspace: state.currentWorkspace, tab: def
                        ))
                    }
                }
                if let tab = state.currentTab() {
                    Image(systemName: "chevron.forward")
                        .scaledSystem(10, weight: .semibold)
                        .foregroundStyle(V2Theme.tertiaryText)
                    breadcrumbButton(
                        icon: nil,
                        label: tab.title,
                        tooltip: "Refresh \(tab.title)"
                    ) {
                        state.refreshTick &+= 1
                    }
                }
            }
            .frame(minWidth: 180, alignment: .leading)

            Button {
                state.paletteOpen = true
            } label: {
                HStack(spacing: 8) {
                    Image(systemName: "magnifyingglass")
                        .scaledSystem(13, weight: .medium)
                        .foregroundStyle(V2Theme.mutedText)
                    Text(String(localized: "ui.V2CommandBar.jump.to.anything", defaultValue: "Jump to anything"))
                        .scaledSystem(14)
                        .foregroundStyle(V2Theme.mutedText)
                    Spacer()
                    HStack(spacing: 2) {
                        ShortcutChip("⌘"); ShortcutChip("⇧"); ShortcutChip("P")
                    }
                }
                .padding(.horizontal, 12)
                .padding(.vertical, 8)
                .background(V2Theme.panelBackground)
                .overlay(
                    RoundedRectangle(cornerRadius: V2Theme.smallCornerRadius)
                        .stroke(V2Theme.panelBorder, lineWidth: 1)
                )
                .clipShape(RoundedRectangle(cornerRadius: V2Theme.smallCornerRadius))
            }
            .buttonStyle(.plain)
            .frame(maxWidth: 480)
            .accessibilityLabel(String(localized: "ui.V2CommandBar.command.palette.press.command.shift.p.or", defaultValue: "Command palette. Press Command Shift P or Command K to open."))

            Spacer()

            // Trailing icon cluster keeps `.layoutPriority(1)` so that
            // even if the breadcrumb or a future workspace title widens
            // unexpectedly (long localizations, accessibility text
            // scaling), the theme / help / settings buttons keep their
            // 32×32 slots at the right edge and stay reachable.
            HStack(spacing: 6) {
                IconButton(icon: schemeIcon, tooltip: schemeTooltip) {
                    toggleScheme()
                }
                IconButton(icon: "questionmark.circle", tooltip: "Help & Docs") {
                    state.goto(V2NavigationDestination(workspace: .docs))
                }
                IconButton(icon: "gearshape", tooltip: "Open Settings  ⌘,") {
                    V2SettingsBridge.openSettings()
                }
            }
            .layoutPriority(1)
        }
        .padding(.horizontal, 16)
        .frame(height: V2Theme.topBarHeight)
        .background(V2Theme.sidebarBackground.opacity(0.6))
        .overlay(
            Rectangle().fill(V2Theme.panelBorder).frame(height: 1),
            alignment: .bottom
        )
    }

    private func breadcrumbButton(icon: String?, label: String, tooltip: String, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            HStack(spacing: 6) {
                if let icon {
                    Image(systemName: icon)
                        .scaledSystem(12, weight: .medium)
                        .foregroundStyle(V2Theme.mutedText)
                }
                Text(label)
                    .scaledSystem(13, weight: .medium)
                    .foregroundStyle(V2Theme.neutral)
            }
            .padding(.horizontal, 7)
            .padding(.vertical, 3)
            .clipShape(RoundedRectangle(cornerRadius: 4))
            .contentShape(Rectangle())
        }
        .buttonStyle(BreadcrumbButtonStyle())
        .help(tooltip)
        .accessibilityLabel(tooltip)
    }

    private func navButton(icon: String, enabled: Bool, tooltip: String, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            Image(systemName: icon)
                .scaledSystem(12, weight: .semibold)
                .foregroundStyle(enabled ? V2Theme.neutral : V2Theme.tertiaryText)
                .frame(width: 28, height: 28)
                .background(V2Theme.panelBackground.opacity(enabled ? 1.0 : 0.4))
                .overlay(
                    RoundedRectangle(cornerRadius: V2Theme.smallCornerRadius)
                        .stroke(V2Theme.panelBorder, lineWidth: 1)
                )
                .clipShape(RoundedRectangle(cornerRadius: V2Theme.smallCornerRadius))
                .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .disabled(!enabled)
        .help(tooltip)
        .accessibilityLabel(tooltip)
    }
}

private struct BreadcrumbButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .background(configuration.isPressed
                        ? V2Theme.activeBackground
                        : Color.clear)
            .clipShape(RoundedRectangle(cornerRadius: 4))
    }
}

private struct ShortcutChip: View {
    let label: String
    init(_ label: String) { self.label = label }
    var body: some View {
        Text(label)
            .scaledSystem(10, weight: .semibold)
            .foregroundStyle(V2Theme.tertiaryText)
            .padding(.horizontal, 4)
            .padding(.vertical, 1)
            .background(V2Theme.hoverBackground)
            .clipShape(RoundedRectangle(cornerRadius: 3))
    }
}

private struct IconButton: View {
    let icon: String
    let tooltip: String
    let action: () -> Void
    @State private var hovering: Bool = false

    var body: some View {
        Button(action: action) {
            Image(systemName: icon)
                .scaledSystem(13, weight: .semibold)
                .foregroundStyle(hovering ? V2Theme.primaryText : V2Theme.mutedText)
                .frame(width: 32, height: 32)
                .background(hovering ? V2Theme.activeBackground : V2Theme.panelBackground)
                .overlay(
                    RoundedRectangle(cornerRadius: V2Theme.smallCornerRadius)
                        .stroke(V2Theme.panelBorder, lineWidth: 1)
                )
                .clipShape(RoundedRectangle(cornerRadius: V2Theme.smallCornerRadius))
                .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .onHover { hovering = $0 }
        .help(tooltip)
        .accessibilityLabel(tooltip)
    }
}

