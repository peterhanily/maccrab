// HawkEyeApp.swift
// HawkEyeApp
//
// Main entry point for the HawkEye macOS status bar application.
// Uses the SwiftUI App lifecycle with MenuBarExtra (macOS 13+).

import SwiftUI

@main
struct HawkEyeApp: App {
    @StateObject private var appState = AppState()
    @Environment(\.openWindow) private var openWindow

    var body: some Scene {
        // Status bar menu -- always visible in the menu bar.
        MenuBarExtra {
            StatusBarMenu(appState: appState)
        } label: {
            // Hawk eye icon: eye with magnifying glass (security monitoring)
            Label("HawkEye", systemImage: "eye.trianglebadge.exclamationmark")
                .labelStyle(.iconOnly)
        }

        // Main dashboard window (opened from the status bar menu).
        Window("HawkEye Dashboard", id: "dashboard") {
            MainView(appState: appState)
        }
        .defaultSize(width: 1000, height: 700)

        // Settings window (Cmd+,).
        Settings {
            SettingsView(appState: appState)
        }
    }
}
