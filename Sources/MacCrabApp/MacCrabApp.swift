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

            let bubbleView = SpeechBubbleWrapper(content: popoverView)
            let hostingController = NSHostingController(rootView: bubbleView)
            let contentSize = NSSize(width: 340, height: 240)
            hostingController.preferredContentSize = contentSize

            // Use a floating panel positioned in the top-right corner
            guard let screen = NSScreen.main else { return }
            let screenFrame = screen.visibleFrame
            let panelX = screenFrame.maxX - contentSize.width - 16
            let panelY = screenFrame.maxY - contentSize.height - 8
            let panelFrame = NSRect(x: panelX, y: panelY, width: contentSize.width, height: contentSize.height)

            let panel = NSPanel(
                contentRect: panelFrame,
                styleMask: [.nonactivatingPanel, .titled, .closable, .fullSizeContentView],
                backing: .buffered,
                defer: false
            )
            panel.contentViewController = hostingController
            panel.level = .floating
            panel.isFloatingPanel = true
            panel.titleVisibility = .hidden
            panel.titlebarAppearsTransparent = true
            panel.isMovableByWindowBackground = true
            panel.backgroundColor = .clear
            panel.isOpaque = false
            panel.hasShadow = true
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

// MARK: - Speech Bubble Wrapper

struct SpeechBubbleWrapper<Content: View>: View {
    let content: Content

    var body: some View {
        VStack(spacing: 0) {
            // Triangle tail pointing up (toward the menu bar crab)
            BubbleTail()
                .fill(Color.white)
                .frame(width: 20, height: 10)
                .padding(.trailing, 40)
                .frame(maxWidth: .infinity, alignment: .trailing)

            // Main bubble body
            content
                .padding(0)
                .background(Color.white)
                .clipShape(RoundedRectangle(cornerRadius: 14))
                .shadow(color: .black.opacity(0.15), radius: 12, x: 0, y: 4)
                .shadow(color: .black.opacity(0.05), radius: 2, x: 0, y: 1)
        }
        .padding(8)
    }
}

/// A small triangle shape for the speech bubble tail
struct BubbleTail: Shape {
    func path(in rect: CGRect) -> Path {
        var path = Path()
        path.move(to: CGPoint(x: rect.midX, y: rect.minY))
        path.addLine(to: CGPoint(x: rect.maxX, y: rect.maxY))
        path.addLine(to: CGPoint(x: rect.minX, y: rect.maxY))
        path.closeSubpath()
        return path
    }
}

// MARK: - Alert Popover View (Speech Bubble Content)

struct AlertPopoverView: View {
    let alert: AlertViewModel
    let onDismiss: () -> Void
    let onShowDashboard: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            // Header with severity badge
            HStack(spacing: 8) {
                Circle()
                    .fill(alert.severityColor)
                    .frame(width: 12, height: 12)

                Text(alert.severity == .critical ? "CRITICAL" : "HIGH")
                    .font(.system(.caption, design: .rounded, weight: .bold))
                    .foregroundColor(alert.severityColor)

                Spacer()

                Text(alert.timeAgoString)
                    .font(.caption2)
                    .foregroundColor(.secondary)

                Button(action: onDismiss) {
                    Image(systemName: "xmark.circle.fill")
                        .foregroundColor(.secondary)
                        .font(.caption)
                }
                .buttonStyle(.plain)
            }

            // Rule title
            Text(alert.ruleTitle)
                .font(.system(.body, weight: .semibold))
                .foregroundColor(.primary)
                .lineLimit(2)

            // Process info
            if !alert.processName.isEmpty {
                HStack(spacing: 4) {
                    Image(systemName: "gearshape.fill")
                        .font(.caption2)
                        .foregroundColor(.secondary)
                    Text(alert.processName)
                        .font(.caption)
                        .foregroundColor(.secondary)
                        .lineLimit(1)
                }
            }

            // Description (truncated)
            if !alert.description.isEmpty {
                Text(alert.description)
                    .font(.caption)
                    .foregroundColor(.secondary)
                    .lineLimit(3)
            }

            // MITRE badge
            if !alert.mitreTechniques.isEmpty {
                HStack(spacing: 4) {
                    Image(systemName: "shield.fill")
                        .font(.caption2)
                        .foregroundColor(.orange)
                    Text(alert.mitreTechniques.split(separator: ",").first.map(String.init) ?? "")
                        .font(.system(.caption2, design: .monospaced))
                        .foregroundColor(.orange)
                }
            }

            Divider()

            // Action buttons
            HStack(spacing: 12) {
                Button(action: onShowDashboard) {
                    Label("View in Dashboard", systemImage: "arrow.right.circle")
                        .font(.caption)
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.small)

                Button(action: onDismiss) {
                    Text("Dismiss")
                        .font(.caption)
                }
                .controlSize(.small)
            }
        }
        .padding(14)
        .frame(width: 320)
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
