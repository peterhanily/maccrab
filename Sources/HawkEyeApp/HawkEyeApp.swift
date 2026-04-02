// HawkEyeApp.swift
// HawkEyeApp

import SwiftUI
import AppKit

@main
struct HawkEyeApp: App {
    @StateObject private var appState = AppState()
    @NSApplicationDelegateAdaptor(AppDelegate.self) var appDelegate

    var body: some Scene {
        // Main dashboard window — opens on launch.
        WindowGroup("HawkEye Dashboard") {
            MainView(appState: appState)
                .frame(minWidth: 900, minHeight: 600)
                .onAppear {
                    appDelegate.setupStatusBar(appState: appState)
                }
        }

        // Settings window (Cmd+,).
        Settings {
            SettingsView(appState: appState)
        }
    }
}

// MARK: - App Delegate with Status Bar

class AppDelegate: NSObject, NSApplicationDelegate {
    private var statusItem: NSStatusItem?
    private var appState: AppState?

    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApplication.shared.activate(ignoringOtherApps: true)
    }

    func setupStatusBar(appState: AppState) {
        guard statusItem == nil else { return }
        self.appState = appState

        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        if let button = statusItem?.button {
            button.image = NSImage(systemSymbolName: "eye.trianglebadge.exclamationmark",
                                   accessibilityDescription: "HawkEye")
        }

        let menu = NSMenu()
        menu.addItem(NSMenuItem(title: "HawkEye Active", action: nil, keyEquivalent: ""))
        menu.addItem(NSMenuItem.separator())
        menu.addItem(NSMenuItem(title: "Show Dashboard", action: #selector(showDashboard), keyEquivalent: "d"))
        menu.addItem(NSMenuItem(title: "Quit", action: #selector(quit), keyEquivalent: "q"))
        statusItem?.menu = menu
    }

    @objc private func showDashboard() {
        NSApplication.shared.activate(ignoringOtherApps: true)
        for window in NSApplication.shared.windows where window.title.contains("HawkEye") {
            window.makeKeyAndOrderFront(nil)
            return
        }
    }

    @objc private func quit() {
        NSApplication.shared.terminate(nil)
    }

    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        if !flag { showDashboard() }
        return true
    }
}
