// MacCrabApp.swift
// MacCrabApp

import SwiftUI
import AppKit

@main
struct MacCrabApp: App {
    @StateObject private var appState = AppState()
    @NSApplicationDelegateAdaptor(AppDelegate.self) var appDelegate

    var body: some Scene {
        // Main dashboard window — opens on launch.
        WindowGroup("MacCrab Dashboard") {
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

// MARK: - App Delegate with Status Bar + Alert Popover

class AppDelegate: NSObject, NSApplicationDelegate {
    private var statusItem: NSStatusItem?
    private var appState: AppState?
    private var popover: NSPopover?
    private var dismissTimer: Timer?
    private var lastPopoverAlertId: String?

    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApplication.shared.activate(ignoringOtherApps: true)
        // Create the status bar item immediately — don't wait for window onAppear
        createStatusBarItem()
    }

    @MainActor func setupStatusBar(appState: AppState) {
        self.appState = appState
        // Register callback for critical alert popups
        appState.onCriticalAlert = { [weak self] alert in
            self?.showAlertPopover(alert: alert)
        }
    }

    private func createStatusBarItem() {
        guard statusItem == nil else { return }
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        if let button = statusItem?.button {
            button.title = "🦀"
            button.font = NSFont.systemFont(ofSize: 14)
        }

        // Attach a menu — clicking the crab opens this menu
        let menu = NSMenu()
        menu.addItem(NSMenuItem(title: "🦀 MacCrab", action: nil, keyEquivalent: ""))
        menu.addItem(NSMenuItem.separator())

        let dashboardItem = NSMenuItem(title: "Show Dashboard", action: #selector(showDashboard), keyEquivalent: "d")
        dashboardItem.target = self
        menu.addItem(dashboardItem)

        let settingsItem = NSMenuItem(title: "Settings...", action: #selector(openSettings), keyEquivalent: ",")
        settingsItem.target = self
        menu.addItem(settingsItem)

        menu.addItem(NSMenuItem.separator())

        let quitItem = NSMenuItem(title: "Quit MacCrab", action: #selector(quit), keyEquivalent: "q")
        quitItem.target = self
        menu.addItem(quitItem)

        statusItem?.menu = menu
    }

    // MARK: - Critical Alert Popover (Crab Speech Bubble)

    func showAlertPopover(alert: AlertViewModel) {
        DispatchQueue.main.async { [weak self] in
            guard let self else { return }
            guard alert.id != self.lastPopoverAlertId else { return }
            self.lastPopoverAlertId = alert.id

            // Close any existing alert panel
            self.alertPanel?.close()
            self.dismissTimer?.invalidate()

            let popoverView = AlertPopoverView(alert: alert, onDismiss: { [weak self] in
                self?.alertPanel?.close()
            }, onShowDashboard: { [weak self] in
                self?.alertPanel?.close()
                self?.showDashboard()
            })

            let hostingController = NSHostingController(rootView: popoverView)
            let contentSize = NSSize(width: 360, height: 200)
            hostingController.preferredContentSize = contentSize

            // Use a floating panel positioned in the top-right corner
            guard let screen = NSScreen.main else { return }
            let screenFrame = screen.visibleFrame
            let panelX = screenFrame.maxX - contentSize.width - 16
            let panelY = screenFrame.maxY - contentSize.height - 8
            let panelFrame = NSRect(x: panelX, y: panelY, width: contentSize.width, height: contentSize.height)

            let panel = NSPanel(
                contentRect: panelFrame,
                styleMask: [.nonactivatingPanel, .fullSizeContentView, .borderless],
                backing: .buffered,
                defer: false
            )
            panel.contentViewController = hostingController
            panel.level = .floating
            panel.isFloatingPanel = true
            panel.backgroundColor = .white
            panel.hasShadow = true
            panel.isMovableByWindowBackground = true
            // Rounded corners
            panel.contentView?.wantsLayer = true
            panel.contentView?.layer?.cornerRadius = 12
            panel.contentView?.layer?.masksToBounds = true
            panel.orderFrontRegardless()

            self.alertPanel = panel

            // Flash the crab
            self.flashCrab(for: alert.severity)

            // Auto-dismiss after 8 seconds
            self.dismissTimer = Timer.scheduledTimer(withTimeInterval: 8.0, repeats: false) { [weak self] _ in
                self?.alertPanel?.close()
            }
        }
    }
    private var alertPanel: NSPanel?

    private func flashCrab(for severity: Severity) {
        guard let button = statusItem?.button else { return }
        let originalTitle = button.title

        // Pulse the crab with severity indicator
        let icon = severity == .critical ? "🔴🦀" : "🟠🦀"
        button.title = icon

        // Reset after 10 seconds
        DispatchQueue.main.asyncAfter(deadline: .now() + 10) {
            button.title = originalTitle
        }
    }

    // MARK: - Status Bar Actions

    @objc private func statusBarClicked() {
        showDashboard()
    }

    @objc private func showDashboard() {
        // Activate the app first
        NSApp.activate(ignoringOtherApps: true)

        // If windows exist, show them
        let appWindows = NSApp.windows.filter { $0.canBecomeMain }
        if let window = appWindows.first {
            window.makeKeyAndOrderFront(nil)
        } else {
            // No windows — re-open the app which triggers SwiftUI to create a new WindowGroup window
            if let bundleURL = Bundle.main.bundleURL as URL? {
                NSWorkspace.shared.openApplication(at: bundleURL, configuration: NSWorkspace.OpenConfiguration())
            }
        }
    }

    @objc private func openSettings() {
        NSApp.activate(ignoringOtherApps: true)
        // Try multiple approaches to open Settings
        if #available(macOS 14.0, *) {
            NSApp.sendAction(Selector(("showSettingsWindow:")), to: nil, from: nil)
        }
        NSApp.sendAction(Selector(("showPreferencesWindow:")), to: nil, from: nil)
        // Fallback: use keyboard shortcut simulation (Cmd+,)
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.1) {
            if NSApp.windows.filter({ $0.title.lowercased().contains("settings") || $0.title.lowercased().contains("preferences") }).isEmpty {
                let event = NSEvent.keyEvent(with: .keyDown, location: .zero, modifierFlags: .command, timestamp: 0, windowNumber: 0, context: nil, characters: ",", charactersIgnoringModifiers: ",", isARepeat: false, keyCode: 43)
                if let event = event { NSApp.sendEvent(event) }
            }
        }
    }

    @objc private func quit() {
        NSApplication.shared.terminate(nil)
    }

    // Prevent window close from destroying the window — hide it instead
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        return false
    }

    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        if !flag { showDashboard() }
        return true
    }
}

// MARK: - Alert Notification View

struct AlertPopoverView: View {
    let alert: AlertViewModel
    let onDismiss: () -> Void
    let onShowDashboard: () -> Void

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            // Crab icon
            Text("🦀")
                .font(.system(size: 28))
                .frame(width: 36, height: 36)

            // Content
            VStack(alignment: .leading, spacing: 4) {
                // Title row
                HStack {
                    Text("MacCrab")
                        .font(.system(.caption, weight: .semibold))
                        .foregroundColor(.secondary)
                    Spacer()
                    Text(alert.timeAgoString)
                        .font(.caption2)
                        .foregroundColor(Color(.tertiaryLabelColor))
                    Button(action: onDismiss) {
                        Image(systemName: "xmark")
                            .font(.system(size: 9, weight: .bold))
                            .foregroundColor(Color(.tertiaryLabelColor))
                    }
                    .buttonStyle(.plain)
                }

                // Alert title
                Text(alert.ruleTitle)
                    .font(.system(.subheadline, weight: .medium))
                    .foregroundColor(.primary)
                    .lineLimit(2)

                // Description
                if !alert.description.isEmpty {
                    Text(alert.description)
                        .font(.caption)
                        .foregroundColor(.secondary)
                        .lineLimit(2)
                }

                // Bottom row: severity + action
                HStack(spacing: 8) {
                    // Severity pill
                    HStack(spacing: 4) {
                        Circle()
                            .fill(alert.severityColor)
                            .frame(width: 6, height: 6)
                        Text(alert.severity == .critical ? "Critical" : "High")
                            .font(.system(.caption2, weight: .medium))
                            .foregroundColor(alert.severityColor)
                    }
                    .padding(.horizontal, 6)
                    .padding(.vertical, 2)
                    .background(alert.severityColor.opacity(0.1))
                    .clipShape(Capsule())

                    if !alert.processName.isEmpty {
                        Text(alert.processName)
                            .font(.caption2)
                            .foregroundColor(Color(.tertiaryLabelColor))
                            .lineLimit(1)
                    }

                    Spacer()

                    Button(action: onShowDashboard) {
                        Text("View")
                            .font(.system(.caption2, weight: .medium))
                    }
                    .buttonStyle(.borderedProminent)
                    .controlSize(.mini)
                }
                .padding(.top, 2)
            }
        }
        .padding(12)
        .frame(width: 340)
        .preferredColorScheme(.light)
    }
}

// MARK: - AlertViewModel Extensions for Popover

extension AlertViewModel {
    var timeAgoString: String {
        let seconds = Date().timeIntervalSince(timestamp)
        if seconds < 60 { return "just now" }
        if seconds < 3600 { return "\(Int(seconds / 60))m ago" }
        return "\(Int(seconds / 3600))h ago"
    }
}
