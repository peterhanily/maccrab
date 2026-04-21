// MacCrabApp.swift
// MacCrabApp

import SwiftUI
import AppKit
import Sparkle

@main
struct MacCrabApp: App {
    @StateObject private var appState = AppState()
    @StateObject private var sysextManager = SystemExtensionManager()
    @NSApplicationDelegateAdaptor(AppDelegate.self) var appDelegate
    @AppStorage("hasCompletedSetup") private var hasCompletedSetup = false
    @AppStorage("launchAtLogin") private var launchAtLogin: Bool = true
    @State private var showWelcome = false

    // Sparkle auto-updater. `startingUpdater: true` kicks off the first
    // background check about 30s after launch and then every 24h
    // (SUScheduledCheckInterval in Info.plist). The controller retains
    // SPUUpdater + SPUStandardUserDriver for the app's lifetime.
    private let updaterController = SPUStandardUpdaterController(
        startingUpdater: true,
        updaterDelegate: nil,
        userDriverDelegate: nil
    )

    var body: some Scene {
        // Main dashboard window — opens on launch.
        WindowGroup("MacCrab Dashboard") {
            MainView(appState: appState, sysextManager: sysextManager)
                .frame(minWidth: 950, minHeight: 600)
                .onAppear {
                    appDelegate.setupStatusBar(appState: appState, updater: updaterController.updater)
                    // Kick off system-extension activation on first
                    // launch. The manager dedups against an already-
                    // activated extension, so this is also safe on
                    // repeated launches — the request returns
                    // immediately with .completed.
                    sysextManager.activate()
                    // Reconcile the launch-at-login preference with the
                    // actual SMAppService state. First run registers;
                    // subsequent runs are no-ops unless the user changed
                    // the preference externally (e.g., via System
                    // Settings → Login Items directly).
                    LaunchAtLogin.reconcile(preferenceEnabled: launchAtLogin)
                    if !hasCompletedSetup {
                        showWelcome = true
                    }
                }
                .sheet(isPresented: $showWelcome) {
                    WelcomeView(isPresented: $showWelcome, sysextManager: sysextManager)
                }
        }
        .commands {
            // "Check for Updates…" under the application menu next to
            // About. The button greys out while a check is in flight.
            CommandGroup(after: .appInfo) {
                CheckForUpdatesView(updater: updaterController.updater)
            }
        }

        // Settings window (Cmd+,).
        Settings {
            SettingsView(appState: appState)
        }
    }
}

// MARK: - Sparkle "Check for Updates…" menu item

/// Small SwiftUI view that binds a menu button to the Sparkle updater's
/// `canCheckForUpdates` state, so the menu item greys out while a check
/// is already running. Lifted from Sparkle's canonical SwiftUI sample.
private struct CheckForUpdatesView: View {
    @ObservedObject private var viewModel: CheckForUpdatesViewModel
    private let updater: SPUUpdater

    init(updater: SPUUpdater) {
        self.updater = updater
        self.viewModel = CheckForUpdatesViewModel(updater: updater)
    }

    var body: some View {
        Button(String(localized: "menu.checkForUpdates", defaultValue: "Check for Updates…")) {
            updater.checkForUpdates()
        }
        .disabled(!viewModel.canCheckForUpdates)
    }
}

/// Wraps SPUUpdater's `canCheckForUpdates` via KVO so SwiftUI redraws
/// the menu state. NSKeyValueObservation handles the lifetime
/// automatically — drop the `@Published` when the view is deallocated.
private final class CheckForUpdatesViewModel: ObservableObject {
    @Published var canCheckForUpdates = false
    private var observation: NSKeyValueObservation?

    init(updater: SPUUpdater) {
        observation = updater.observe(\.canCheckForUpdates, options: [.initial]) { [weak self] updater, _ in
            self?.canCheckForUpdates = updater.canCheckForUpdates
        }
    }
}

// MARK: - App Delegate with Status Bar + Alert Popover

class AppDelegate: NSObject, NSApplicationDelegate {
    private var statusItem: NSStatusItem?
    private var appState: AppState?
    /// Sparkle updater injected from MacCrabApp so the statusbar menu's
    /// "Check for Updates…" item can trigger a check. Menubar-only apps
    /// (LSUIElement=true) can't receive menu commands via SwiftUI's
    /// `CommandGroup`, so this is the only accessible path.
    private var updater: SPUUpdater?
    private var popover: NSPopover?
    private var dismissTimer: Timer?
    private var lastPopoverAlertId: String?

    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApplication.shared.activate(ignoringOtherApps: true)
        // Create the status bar item immediately — don't wait for window onAppear
        createStatusBarItem()
    }

    @MainActor func setupStatusBar(appState: AppState, updater: SPUUpdater? = nil) {
        self.appState = appState
        if let updater { self.updater = updater }
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

        // Check for Updates… — the only in-UI path to trigger a Sparkle
        // check on a menubar-only app. v1.3.7 shipped with this wired to
        // SwiftUI's CommandGroup(after: .appInfo), which doesn't render
        // in LSUIElement=true apps; v1.3.8 moves it here where users
        // can actually reach it.
        let updateItem = NSMenuItem(title: "Check for Updates…",
                                    action: #selector(checkForUpdates),
                                    keyEquivalent: "")
        updateItem.target = self
        menu.addItem(updateItem)

        menu.addItem(NSMenuItem.separator())

        let quitItem = NSMenuItem(title: "Quit MacCrab", action: #selector(quit), keyEquivalent: "q")
        quitItem.target = self
        menu.addItem(quitItem)

        statusItem?.menu = menu
    }

    @objc private func checkForUpdates() {
        updater?.checkForUpdates()
    }

    /// Callable from anywhere with an NSApp.delegate reference — used by
    /// the Settings "Check for Updates…" button so Sparkle can be triggered
    /// without menu-bar access on a menubar-only app.
    @MainActor func triggerUpdateCheck() {
        updater?.checkForUpdates()
    }

    /// Whether Sparkle is currently capable of checking — mirrors
    /// SPUUpdater.canCheckForUpdates so a UI button can grey itself
    /// when a check is already in flight.
    var canCheckForUpdates: Bool {
        updater?.canCheckForUpdates ?? false
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
            let contentSize = NSSize(width: 344, height: 140)
            hostingController.preferredContentSize = contentSize

            // Use a floating panel positioned in the top-right corner
            guard let screen = NSScreen.main else { return }
            let screenFrame = screen.visibleFrame
            let panelX = screenFrame.maxX - contentSize.width - 16
            let panelY = screenFrame.maxY - contentSize.height - 8
            let panelFrame = NSRect(x: panelX, y: panelY, width: contentSize.width, height: contentSize.height)

            let panel = NSPanel(
                contentRect: panelFrame,
                styleMask: [.nonactivatingPanel, .titled, .fullSizeContentView],
                backing: .buffered,
                defer: false
            )
            panel.contentViewController = hostingController
            panel.level = .floating
            panel.isFloatingPanel = true
            panel.titleVisibility = .hidden
            panel.titlebarAppearsTransparent = true
            panel.backgroundColor = .white
            panel.hasShadow = true
            panel.isMovableByWindowBackground = true
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

    @objc func openSettings() {
        NSApp.activate(ignoringOtherApps: true)
        // Find and trigger the Settings/Preferences menu item from the app menu
        if let appMenu = NSApp.mainMenu?.item(at: 0)?.submenu {
            for item in appMenu.items {
                let title = item.title.lowercased()
                if title.contains("settings") || title.contains("preferences") {
                    appMenu.performActionForItem(at: appMenu.index(of: item))
                    return
                }
            }
        }
        // Fallback: try the standard selector
        if #available(macOS 14.0, *) {
            NSApp.sendAction(Selector(("showSettingsWindow:")), to: nil, from: nil)
        } else {
            NSApp.sendAction(Selector(("showPreferencesWindow:")), to: nil, from: nil)
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
        .padding(.horizontal, 10)
        .padding(.bottom, 10)
        .padding(.top, 2)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
        .background(Color(nsColor: .windowBackgroundColor))
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
