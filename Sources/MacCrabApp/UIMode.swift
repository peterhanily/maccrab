// UIMode.swift
// MacCrabApp
//
// Dashboard complexity modes. Lets home users hide the analyst-heavy
// views (rule browser, AI analysis, threat intel, ES health) without
// deleting them — they're one toggle away in Settings > Appearance.
//
// Default is .advanced so upgrades preserve the full current UX. Users
// can downgrade; new installs can pick a mode from Welcome.

import Foundation

public enum UIMode: String, Codable, Sendable, CaseIterable {
    /// Minimum surface — Overview, Alerts, Prevention, Permissions, Docs.
    /// Target audience: single-user home install, "show me if anything is
    /// wrong" posture.
    case basic

    /// Mid-surface — adds Campaigns, Events, AI Guard, Browser Extensions,
    /// Integrations. Target audience: security-conscious user or a
    /// small-team lead operator.
    case standard

    /// Full surface (15 views). Default. Target audience: detection
    /// engineer, SOC analyst, MacCrab developer.
    case advanced

    public var displayName: String {
        switch self {
        case .basic:    return "Basic"
        case .standard: return "Standard"
        case .advanced: return "Advanced"
        }
    }

    /// One-sentence description shown beside the picker in Settings. Reflects the
    /// real V2 sidebar mapping (see V2Workspace.minimumMode). Everything is always
    /// protected — this only changes which workspaces show in the sidebar.
    public var summary: String {
        switch self {
        case .basic:
            return "Overview, Alerts, System, Docs. For home users."
        case .standard:
            return "Adds Events, Investigation, Detection, Prevention. For lead operators."
        case .advanced:
            return "Adds Forensics + Intelligence — every view. For detection engineers."
        }
    }

    /// Density ordering for visibility comparisons (basic ⊂ standard ⊂ advanced).
    public var rank: Int {
        switch self {
        case .basic:    return 0
        case .standard: return 1
        case .advanced: return 2
        }
    }

    /// AppStorage key used across MainView + SettingsView.
    public static let storageKey = "maccrab.ui.mode"
}
