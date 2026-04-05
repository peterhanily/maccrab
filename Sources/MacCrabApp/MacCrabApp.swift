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
    }

    @MainActor func setupStatusBar(appState: AppState) {
        guard statusItem == nil else { return }
        self.appState = appState

        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        if let button = statusItem?.button {
            button.title = "🦀"
            button.font = NSFont.systemFont(ofSize: 14)
            button.action = #selector(statusBarClicked)
            button.target = self
            button.sendAction(on: [.leftMouseUp, .rightMouseUp])
        }

        let menu = NSMenu()
        menu.addItem(NSMenuItem(title: "🦀 MacCrab Active", action: nil, keyEquivalent: ""))
        menu.addItem(NSMenuItem.separator())
        menu.addItem(NSMenuItem(title: "Show Dashboard", action: #selector(showDashboard), keyEquivalent: "d"))
        menu.addItem(NSMenuItem(title: "Settings...", action: #selector(openSettings), keyEquivalent: ","))
        menu.addItem(NSMenuItem.separator())
        menu.addItem(NSMenuItem(title: "Quit", action: #selector(quit), keyEquivalent: "q"))
        statusItem?.menu = menu

        // Register callback for critical alert popups
        appState.onCriticalAlert = { [weak self] alert in
            self?.showAlertPopover(alert: alert)
        }
    }

    // MARK: - Critical Alert Popover (Crab Speech Bubble)

    func showAlertPopover(alert: AlertViewModel) {
        // Dedup: don't show same alert twice
        guard alert.id != lastPopoverAlertId else { return }
        lastPopoverAlertId = alert.id
        // Dismiss any existing popover
        popover?.close()
        dismissTimer?.invalidate()

        let popoverView = AlertPopoverView(alert: alert, onDismiss: { [weak self] in
            self?.popover?.close()
        }, onShowDashboard: { [weak self] in
            self?.popover?.close()
            self?.showDashboard()
        })

        let hostingController = NSHostingController(rootView: popoverView)
        hostingController.preferredContentSize = NSSize(width: 340, height: 0)

        let pop = NSPopover()
        pop.contentViewController = hostingController
        pop.behavior = .transient
        pop.animates = true
        self.popover = pop

        // Show from the status bar button
        if let button = statusItem?.button {
            pop.show(relativeTo: button.bounds, of: button, preferredEdge: .minY)
        }

        // Flash the crab
        flashCrab(for: alert.severity)

        // Auto-dismiss after 8 seconds
        dismissTimer = Timer.scheduledTimer(withTimeInterval: 8.0, repeats: false) { [weak self] _ in
            self?.popover?.close()
        }
    }

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
        if let event = NSApp.currentEvent, event.type == .rightMouseUp {
            // Right-click shows menu
            statusItem?.button?.performClick(nil)
        } else {
            // Left-click shows dashboard
            showDashboard()
        }
    }

    @objc private func showDashboard() {
        NSApplication.shared.activate(ignoringOtherApps: true)
        for window in NSApplication.shared.windows where window.title.contains("MacCrab") {
            window.makeKeyAndOrderFront(nil)
            return
        }
    }

    @objc private func openSettings() {
        NSApplication.shared.activate(ignoringOtherApps: true)
        if #available(macOS 14.0, *) {
            NSApplication.shared.sendAction(Selector(("showSettingsWindow:")), to: nil, from: nil)
        } else {
            NSApplication.shared.sendAction(Selector(("showPreferencesWindow:")), to: nil, from: nil)
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
