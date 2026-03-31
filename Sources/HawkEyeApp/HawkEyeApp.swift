// HawkEyeApp.swift
// HawkEyeApp
//
// Main entry point for the HawkEye macOS status bar application.
// Uses the SwiftUI App lifecycle with MenuBarExtra (macOS 13+).

import SwiftUI

@main
struct HawkEyeApp: App {
    @StateObject private var appState = AppState()

    var body: some Scene {
        // Status bar menu -- always visible in the menu bar.
        MenuBarExtra {
            StatusBarMenu(appState: appState)
        } label: {
            Image(systemName: appState.statusIcon)
                .symbolRenderingMode(.palette)
        }

        // Main dashboard window (opened from the status bar menu).
        WindowGroup("HawkEye") {
            MainView(appState: appState)
        }

        // Settings window (Cmd+,).
        Settings {
            SettingsView(appState: appState)
        }
    }
}
