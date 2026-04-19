// SystemExtensionPanel.swift
//
// Operator-facing UI for the Endpoint Security system extension
// lifecycle. Shown at the top of the Overview tab while the extension
// isn't active, plus a permanent status chip in the dashboard header.
// The approval prompt happens in System Settings; this panel's job is
// to explain what's happening and offer a "Open System Settings" link
// in case the prompt got dismissed.

import SwiftUI
import AppKit

public struct SystemExtensionPanel: View {
    @ObservedObject var manager: SystemExtensionManager

    public init(manager: SystemExtensionManager) {
        self.manager = manager
    }

    public var body: some View {
        HStack(alignment: .top, spacing: 14) {
            stateIcon
            VStack(alignment: .leading, spacing: 6) {
                HStack(spacing: 8) {
                    Text(headline)
                        .font(.headline)
                    stateBadge
                }
                Text(body(for: manager.state))
                    .font(.subheadline)
                    .foregroundColor(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                actions
            }
            Spacer()
        }
        .padding(16)
        .background(backgroundFill)
        .clipShape(RoundedRectangle(cornerRadius: 10))
        .overlay(
            RoundedRectangle(cornerRadius: 10)
                .stroke(borderColor.opacity(0.35), lineWidth: 1)
        )
    }

    // MARK: - State-driven presentation

    private var headline: String {
        switch manager.state {
        case .unknown, .notActivated:
            return String(localized: "sysext.headline.enable", defaultValue: "Enable Endpoint Security protection")
        case .activating:
            return String(localized: "sysext.headline.activating", defaultValue: "Activating protection")
        case .awaitingApproval:
            return String(localized: "sysext.headline.pending", defaultValue: "Approval required")
        case .activated:
            return String(localized: "sysext.headline.active", defaultValue: "Protection active")
        case .failed:
            return String(localized: "sysext.headline.failed", defaultValue: "Activation failed")
        }
    }

    private func body(for state: SystemExtensionState) -> String {
        switch state {
        case .unknown:
            return String(localized: "sysext.body.checking", defaultValue: "Checking extension state\u{2026}")
        case .notActivated:
            return String(
                localized: "sysext.body.notActivated",
                defaultValue: "MacCrab's detection engine runs as a macOS system extension so it can observe kernel events at the source. The first time you enable it, macOS will ask for your approval in System Settings."
            )
        case .activating:
            return String(
                localized: "sysext.body.activating",
                defaultValue: "Registering the extension with sysextd. If a prompt appears in System Settings, approve it to continue."
            )
        case .awaitingApproval:
            return String(
                localized: "sysext.body.awaitingApproval",
                defaultValue: "Open System Settings > General > Login Items & Extensions > Endpoint Security Extensions and enable MacCrab's extension. Detection won't start until you approve."
            )
        case .activated:
            return String(
                localized: "sysext.body.activated",
                defaultValue: "Kernel events are flowing through the MacCrab agent. All detection tiers are online."
            )
        case .failed(let reason):
            // Reason comes from OSSystemExtensionError and is system-localized.
            return reason
        }
    }

    @ViewBuilder
    private var stateIcon: some View {
        switch manager.state {
        case .activated:
            Image(systemName: "checkmark.shield.fill")
                .font(.system(size: 28))
                .foregroundColor(.green)
        case .awaitingApproval:
            Image(systemName: "hand.raised.fill")
                .font(.system(size: 28))
                .foregroundColor(.orange)
        case .failed:
            Image(systemName: "exclamationmark.shield.fill")
                .font(.system(size: 28))
                .foregroundColor(.red)
        case .activating:
            ProgressView()
                .controlSize(.large)
                .frame(width: 32, height: 32)
        default:
            Image(systemName: "shield")
                .font(.system(size: 28))
                .foregroundColor(.secondary)
        }
    }

    @ViewBuilder
    private var stateBadge: some View {
        Text(stateLabel)
            .font(.caption)
            .fontWeight(.semibold)
            .padding(.horizontal, 8)
            .padding(.vertical, 2)
            .background(borderColor.opacity(0.15))
            .foregroundColor(borderColor)
            .clipShape(Capsule())
    }

    private var stateLabel: String {
        switch manager.state {
        case .unknown: return String(localized: "sysext.state.unknown", defaultValue: "Unknown")
        case .notActivated: return String(localized: "sysext.state.disabled", defaultValue: "Disabled")
        case .activating: return String(localized: "sysext.state.activating", defaultValue: "Activating")
        case .awaitingApproval: return String(localized: "sysext.state.pending", defaultValue: "Pending")
        case .activated: return String(localized: "sysext.state.active", defaultValue: "Active")
        case .failed: return String(localized: "sysext.state.failed", defaultValue: "Failed")
        }
    }

    @ViewBuilder
    private var actions: some View {
        HStack(spacing: 8) {
            switch manager.state {
            case .unknown, .notActivated, .failed:
                Button {
                    manager.activate()
                } label: {
                    Label(
                        String(localized: "sysext.action.enable", defaultValue: "Enable Protection"),
                        systemImage: "shield.checkered"
                    )
                }
                .buttonStyle(.borderedProminent)
            case .awaitingApproval:
                Button {
                    openLoginItemsAndExtensions()
                } label: {
                    Label(
                        String(localized: "sysext.action.openSettings", defaultValue: "Open System Settings"),
                        systemImage: "gearshape"
                    )
                }
                .buttonStyle(.borderedProminent)
                Button(String(localized: "sysext.action.tryAgain", defaultValue: "Try again")) {
                    manager.activate()
                }
                .buttonStyle(.bordered)
            case .activating:
                EmptyView()
            case .activated:
                EmptyView()
            }
        }
    }

    private var backgroundFill: Color {
        switch manager.state {
        case .activated:
            return Color.green.opacity(0.08)
        case .awaitingApproval:
            return Color.orange.opacity(0.08)
        case .failed:
            return Color.red.opacity(0.08)
        default:
            return Color.secondary.opacity(0.06)
        }
    }

    private var borderColor: Color {
        switch manager.state {
        case .activated: return .green
        case .awaitingApproval: return .orange
        case .failed: return .red
        default: return .secondary
        }
    }

    private func openLoginItemsAndExtensions() {
        // macOS 13+ uses x-apple.systempreferences URL scheme. The exact
        // extension subpane moved around between 13/14/15; fall back to
        // a more generic target if the extension-specific one fails.
        let urls = [
            "x-apple.systempreferences:com.apple.LoginItems-Settings.extension",
            "x-apple.systempreferences:com.apple.preference.security",
            "x-apple.systempreferences:com.apple.ExtensionsPreferences",
        ]
        for raw in urls {
            if let url = URL(string: raw), NSWorkspace.shared.open(url) {
                return
            }
        }
    }
}
