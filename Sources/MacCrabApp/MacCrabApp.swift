// MacCrabApp.swift
// MacCrabApp

import SwiftUI
import AppKit
import Sparkle
import MacCrabForensics

@main
struct MacCrabApp: App {
    // v1.4.2: sync rules from the app bundle to the installed
    // rules-dir. v1.11.1 (audit launch-perf): moved off the
    // MacCrabApp.init() main-thread path to a Task.detached fired
    // from the WindowGroup's .onAppear (line ~95). Pre-fix the
    // sync ran SYNCHRONOUSLY on main BEFORE SwiftUI rendered the
    // first frame — on first install / Sparkle update it ran
    // SHA-256 manifest verification + copied hundreds of rule
    // files to /Library/Application Support/MacCrab/compiled_rules/,
    // producing a multi-second beachball before the dashboard
    // window even appeared. Now: window paints first, sync runs
    // in the background, daemon SIGHUP at sync completion picks up
    // the new rules. Worst case the user sees rule list briefly
    // populated from the prior installed corpus while the new one
    // copies in; the dashboard's mtime-gated AppState.loadRules
    // refresh picks up the new set on its next 5s tick.
    init() {}

    @StateObject private var appState = AppState()
    @StateObject private var sysextManager = SystemExtensionManager()
    @NSApplicationDelegateAdaptor(AppDelegate.self) var appDelegate
    @AppStorage("hasCompletedSetup") private var hasCompletedSetup = false
    @AppStorage("launchAtLogin") private var launchAtLogin: Bool = true
    @State private var showWelcome = false
    @Environment(\.scenePhase) private var scenePhase

    /// True when the running MacCrab.app was installed via Homebrew Cask
    /// (binary lives under a `/Caskroom/` path). v1.7.9: detected at launch
    /// so we can disable Sparkle's automatic background checks for brew
    /// users. Without this, the v1.6.13 → v1.7.5 channel-drift incident
    /// recurs: Sparkle silently bumps the .app to v1.7.x while brew still
    /// thinks it owns v1.6.x, then `brew upgrade` overwrites the newer
    /// Sparkle-installed binary with the older brew-formula one.
    static let isBrewInstalled: Bool = {
        Bundle.main.bundleURL.path.contains("/Caskroom/")
    }()

    // Sparkle auto-updater. `startingUpdater` is gated on installation
    // source: brew-installed users see "Check for Updates" still
    // available (manual click) but won't get auto-bumped behind brew's
    // back. DMG-installed users get the normal 24h auto-check cadence.
    private let updaterController: SPUStandardUpdaterController = {
        let controller = SPUStandardUpdaterController(
            startingUpdater: !MacCrabApp.isBrewInstalled,
            updaterDelegate: nil,
            userDriverDelegate: nil
        )
        if MacCrabApp.isBrewInstalled {
            controller.updater.automaticallyChecksForUpdates = false
        }
        return controller
    }()

    var body: some Scene {
        // Main dashboard window — opens on launch.
        WindowGroup("MacCrab Dashboard") {
            V2RootView(appState: appState)
                // Single source of truth for the dashboard's minimum
                // window size. Pre-v1.12.9 there were two competing
                // minimums — 950×600 here and 1280×800 inside
                // V2DashboardShell — which let the window drag smaller
                // than the content's natural width. The inner frame
                // forced the HStack to lay out at 1280pt regardless of
                // window size, so the top bar's trailing icon buttons
                // (theme / help / settings) ended up past the window's
                // right edge, unreachable. Now only one frame governs:
                // window can't shrink below 1180×760, and the inner
                // shell renders to whatever the window gives it.
                .frame(minWidth: 1180, minHeight: 760)
                // Tint every native control (buttons, links, toggles,
                // progress views, sliders) with MacCrab's brand orange,
                // mirroring the `--accent` color used on maccrab.com.
                // Cascades through the entire view hierarchy so custom
                // views that want the brand color can omit explicit
                // .foregroundStyle(MacCrabTheme.accent) and let the tint
                // do it.
                .tint(MacCrabTheme.accent)
                .onAppear {
                    appDelegate.setupStatusBar(appState: appState, updater: updaterController.updater)
                    // v1.12.0 fix (rule sync visibility on menubar apps):
                    // RuleBundleInstaller.syncIfNeeded() moved from this
                    // .onAppear to AppDelegate.applicationDidFinishLaunching.
                    // V2RootView .onAppear only fires when the user opens
                    // the dashboard window — for an LSUIElement=true
                    // menubar app, a user who never clicks the menubar
                    // icon will never see the rule sync run. The sysext
                    // continues to read whatever the cask postflight (or
                    // a previous version's sync) wrote. Moving to the
                    // app-level launch hook makes the sync independent of
                    // window state.
                    // Kick off system-extension activation on first
                    // launch. The manager dedups against an already-
                    // activated extension, so this is also safe on
                    // repeated launches — the request returns
                    // immediately with .completed.
                    sysextManager.activate()
                    // v1.4.3 watchdog: AppState polls the sysext
                    // heartbeat; when it's stale, this callback gets
                    // invoked so we can respawn the sysext without
                    // user intervention. Idempotent — sysextManager
                    // internally dedups a redundant activation when
                    // the ext is already running.
                    appState.sysextWatchdogActivate = { [weak sysextManager] in
                        sysextManager?.activate()
                    }
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
                // Pause AppState's 10-second DB poll when the dashboard
                // window is hidden or the app is backgrounded. MacCrab is
                // LSUIElement=true so closing the dashboard leaves the
                // sysext running — we just don't need to keep polling for
                // UI state updates that nobody is looking at.
                .onChange(of: scenePhase) { newPhase in
                    switch newPhase {
                    case .active:   appState.startPolling()
                    case .inactive, .background: appState.stopPolling()
                    @unknown default: break
                    }
                }
                // Upgrade-handoff: hush banner posting while a sysext
                // activation/replace is in flight, so a freshly-launched
                // post-upgrade app doesn't double-post over the OLD resident
                // sysext's osascript banners. The gate is fail-open (absolute
                // deadline in armNotifierHandoffGate) and lifts the instant
                // the request settles — so a normal launch is a brief no-op.
                .onChange(of: sysextManager.state) { newState in
                    switch newState {
                    case .activating:
                        appDelegate.armNotifierHandoffGate()
                    case .activated, .notActivated, .failed:
                        appDelegate.clearNotifierHandoffGate()
                    case .unknown, .awaitingApproval:
                        break  // bounded by the gate's deadline
                    }
                }
                // maccrab:// deep links (APPCORE-01). The OS delivers the
                // URL here; V2 owns its navigation state via @StateObject,
                // so we cross the module boundary via NotificationCenter —
                // same bridge pattern as maccrab.openAlert. Bring the
                // dashboard window forward (LSUIElement menubar app) then
                // hand the URL to V2DashboardShell, which calls
                // state.goto(url:). Unknown/malformed links are handled
                // safely there (error toast, no crash).
                .onOpenURL { url in
                    NSApp.activate(ignoringOtherApps: true)
                    // v1.17 (issue #2): uninstall-assist. OSSystemExtensionRequest
                    // deactivation must be submitted by the signed app running as
                    // the console user — scripts/uninstall.sh (sudo bash) can't do
                    // it. The uninstaller opens maccrab://deactivate; we submit the
                    // request here. It's async + shows a system approval modal and
                    // may resolve only after a reboot, so we do NOT force-quit —
                    // the user reads the status/reboot guidance and the uninstaller
                    // verifies via `systemextensionsctl list`.
                    if url.host == "deactivate" {
                        sysextManager.deactivate()
                        return
                    }
                    NotificationCenter.default.post(
                        name: Notification.Name("maccrab.openURL"),
                        object: nil,
                        userInfo: ["url": url]
                    )
                }
        }
        .commands {
            // Replace the default "About MacCrab" with a panel that
            // includes a clickable maccrab.com link in the credits
            // field. Keeps the native About UX (same window chrome,
            // same keyboard behavior) but adds the website link users
            // expect from a modern Mac app.
            CommandGroup(replacing: .appInfo) {
                Button("About MacCrab") {
                    MacCrabApp.showAboutPanel()
                }
            }
            // "Check for Updates…" under the application menu next to
            // About. The button greys out while a check is in flight.
            CommandGroup(after: .appInfo) {
                CheckForUpdatesView(updater: updaterController.updater)
            }
            // Help menu: direct link to maccrab.com. Standard macOS
            // convention — apps with a website put "Visit XXX Website"
            // in the Help menu so users can find it consistently.
            CommandGroup(replacing: .help) {
                Button("Visit maccrab.com") {
                    if let url = URL(string: "https://maccrab.com") {
                        NSWorkspace.shared.open(url)
                    }
                }
                Button("MacCrab Documentation") {
                    if let url = URL(string: "https://github.com/peterhanily/maccrab#readme") {
                        NSWorkspace.shared.open(url)
                    }
                }
                Divider()
                Button("Report an Issue…") {
                    if let url = URL(string: "https://github.com/peterhanily/maccrab/issues/new") {
                        NSWorkspace.shared.open(url)
                    }
                }
            }
        }

        // Settings window (Cmd+,).
        Settings {
            SettingsView(appState: appState, sysextManager: sysextManager)
        }
    }

    /// Show the About MacCrab panel with a clickable maccrab.com link in
    /// the credits. Called from the `CommandGroup(replacing: .appInfo)`
    /// button above. Reaches for `NSApp.orderFrontStandardAboutPanel`
    /// because a SwiftUI-native "About" window doesn't exist yet (as of
    /// macOS 15) — the AppKit panel is the right primitive and gets us
    /// Dark Mode, keyboard behavior, and localization for free.
    @MainActor static func showAboutPanel() {
        let info = Bundle.main.infoDictionary ?? [:]
        let version = info["CFBundleShortVersionString"] as? String ?? "?"
        let build = info["CFBundleVersion"] as? String ?? ""
        let versionString = build == version ? version : "\(version) (\(build))"

        // Credits: clickable maccrab.com link + a one-line tagline.
        // NSMutableAttributedString + NSAttributedString.Key.link is the
        // standard way to make rich links render in the About panel.
        let credits = NSMutableAttributedString()
        let tagline = NSAttributedString(
            string: "Local-first macOS threat detection.\nNo cloud, no SIEM, no telemetry.\n\n",
            attributes: [
                .font: NSFont.systemFont(ofSize: 11),
                .foregroundColor: NSColor.labelColor,
                .paragraphStyle: {
                    let p = NSMutableParagraphStyle()
                    p.alignment = .center
                    return p
                }()
            ]
        )
        credits.append(tagline)
        let website = NSAttributedString(
            string: "maccrab.com",
            attributes: [
                .link: URL(string: "https://maccrab.com")!,
                .font: NSFont.systemFont(ofSize: 11, weight: .medium),
                .paragraphStyle: {
                    let p = NSMutableParagraphStyle()
                    p.alignment = .center
                    return p
                }()
            ]
        )
        credits.append(website)

        NSApp.orderFrontStandardAboutPanel(options: [
            .applicationName: "MacCrab",
            .applicationVersion: versionString,
            .version: "",  // hide the parenthetical build number duplication
            .credits: credits,
            .init(rawValue: "Copyright"): "© 2026 CaddyLabs",
        ])
        NSApp.activate(ignoringOtherApps: true)
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
    /// Polls AppState's health signals and flips the statusbar icon
    /// between the healthy crab 🦀 and a warning variant ⚠️🦀 when
    /// detection is degraded (zero rules loaded, stale heartbeat, or
    /// storage errors accumulating). Introduced in v1.4.3 so users
    /// who glance at the menubar immediately know protection is off.
    private var statusBarHealthTimer: Timer?

    /// v1.17 (issue #2): posts MacCrab-attributed OS banners via
    /// UNUserNotificationCenter, driven by the process-lifetime
    /// statusBarHealthTimer below (works while the dashboard window is
    /// closed). Replaces the daemon's osascript/System-Events path.
    private var alertNotifier: AlertNotifier?

    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApplication.shared.activate(ignoringOtherApps: true)
        // Create the status bar item immediately — don't wait for window onAppear
        createStatusBarItem()
        // v1.12.0 fix: rule sync runs here (was V2RootView.onAppear, which
        // never fires for menubar-only users who don't click into the
        // dashboard). Task.detached so the launch sequence isn't blocked;
        // syncIfNeeded prompts for admin via osascript only when the
        // installed rule version differs from the bundled version.
        Task.detached(priority: .utility) {
            RuleBundleInstaller.syncIfNeeded()
        }
        // v1.18: forensic-scan retention. The "Scan retention" setting
        // (forensics.retentionDays) promised cleanup "the next time the
        // dashboard opens", but only the manual "Run cleanup now" button was
        // ever wired. Run the sweep once at launch. Default 365d is
        // registered here so an unset key reads as 1 year (matching the
        // SettingsView @AppStorage default); "Never" (0) opts out.
        Task.detached(priority: .utility) {
            UserDefaults.standard.register(defaults: ["forensics.retentionDays": 365])
            let days = UserDefaults.standard.integer(forKey: "forensics.retentionDays")
            guard days > 0 else { return }
            let cutoff = Date().addingTimeInterval(-Double(days) * 86_400)
            let mgr = CaseManager(casesRoot: CaseDirectoryLayout.defaultCasesRoot, dekVault: KeychainDEKVault())
            let result = await mgr.pruneCases(olderThan: cutoff)
            if !result.deleted.isEmpty {
                NSLog("[MacCrab] Forensic scan retention: deleted \(result.deleted.count) scan(s) older than \(days)d")
            }
        }
    }

    @MainActor func setupStatusBar(appState: AppState, updater: SPUUpdater? = nil) {
        self.appState = appState
        if let updater { self.updater = updater }
        // Register callback for critical alert popups
        appState.onCriticalAlert = { [weak self] alert in
            self?.showAlertPopover(alert: alert)
        }
        // v1.17 (issue #2): OS banners are now posted by the app via
        // UNUserNotificationCenter (attributed to MacCrab, controllable
        // in System Settings, and gone on uninstall) rather than the
        // daemon's osascript → "System Events". Falls back to the in-app
        // popover when notification authorization is denied/undetermined.
        let notifier = AlertNotifier()
        notifier.onFallback = { [weak self] alert in
            guard let self, let vm = self.appState?.alertToViewModel(alert) else { return }
            self.showAlertPopover(alert: vm)
        }
        // Banner tap → bring the dashboard window forward THEN hand off to
        // V2 via the same bridge the in-app popover uses
        // (AlertPopoverView.onShowDashboard). showDashboard() first so the
        // WindowGroup is mounted to receive maccrab.openAlert.
        notifier.onOpenAlert = { [weak self] alertId in
            guard let self else { return }
            self.showDashboard()
            NotificationCenter.default.post(
                name: Notification.Name("maccrab.openAlert"),
                object: nil,
                userInfo: ["alertId": alertId]
            )
        }
        self.alertNotifier = notifier
        Task { await notifier.requestAuthorization() }
        // Start the statusbar health poller. Uses a 5s cadence so the
        // icon updates quickly after the first refresh() but doesn't
        // fight the 10s AppState poll. Fires immediately on setup so a
        // degraded cold-start state is visible without waiting. This is
        // a process-lifetime timer (NOT scenePhase-gated), so it also
        // drives the notifier's poll while the dashboard window is closed.
        statusBarHealthTimer?.invalidate()
        statusBarHealthTimer = Timer.scheduledTimer(withTimeInterval: 5.0, repeats: true) { [weak self] _ in
            self?.updateStatusBarIcon()
            Task { await self?.alertNotifier?.tick() }
        }
        updateStatusBarIcon()
    }

    /// Upgrade-handoff gate for banner posting (see
    /// `AlertNotifier.suppressUntil`). Armed when the sysext enters
    /// `.activating` and cleared when it settles. The 30s ABSOLUTE deadline
    /// is the fail-open ceiling: if the activation request never settles,
    /// posting resumes regardless. Near-instant on a normal launch (an
    /// already-active extension settles in a tick or two); only meaningful
    /// during a real `.replace` after an app upgrade.
    @MainActor func armNotifierHandoffGate() {
        alertNotifier?.suppressUntil = Date().addingTimeInterval(30)
    }

    @MainActor func clearNotifierHandoffGate() {
        alertNotifier?.suppressUntil = nil
    }

    /// Flip the statusbar title to the healthy crab or the warning
    /// variant based on AppState's current health signals. Source of
    /// truth for "is protection degraded" is `isProtectionDegraded`
    /// on AppState — see that property for the exact conditions.
    @MainActor private func updateStatusBarIcon() {
        guard let button = statusItem?.button else { return }
        let degraded = appState?.isProtectionDegraded ?? false
        Self.applyStatusBarImage(to: button, degraded: degraded)
    }

    /// Crab emoji in the menu bar — the brand identity. We tried a
    /// template-rendered SF Symbol shield in v1.6.2 and got immediate
    /// user feedback: "bring back the crab." The tradeoff with emoji is
    /// that it renders in color regardless of menu bar theme (macOS
    /// doesn't template-render emoji), but that's explicitly fine here —
    /// many popular Mac apps (1Password, Discord, Notion) use colorful
    /// menu-bar icons for the same brand-recognition reason.
    ///
    /// Degraded state prepends a warning triangle; healthy is just the
    /// crab. Both variants carry an explicit accessibility description
    /// via `setAccessibilityLabel` so VoiceOver users get a meaningful
    /// announcement instead of "crab emoji."
    @MainActor private static func applyStatusBarImage(to button: NSStatusBarButton, degraded: Bool) {
        let title = degraded ? "⚠️🦀" : "🦀"
        let label = degraded ? "MacCrab — protection degraded" : "MacCrab"
        if button.title != title {
            button.title = title
        }
        button.image = nil
        button.imagePosition = .noImage
        button.font = NSFont.systemFont(ofSize: 14)
        button.setAccessibilityLabel(label)
    }

    @MainActor private func createStatusBarItem() {
        guard statusItem == nil else { return }
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        if let button = statusItem?.button {
            Self.applyStatusBarImage(to: button, degraded: false)
        }

        // Attach a menu — clicking the crab opens this menu
        let menu = NSMenu()
        menu.addItem(NSMenuItem(title: "🦀 MacCrab", action: nil, keyEquivalent: ""))
        menu.addItem(NSMenuItem.separator())

        // Helper: build a menu item with an SF Symbol leading icon
        // so every actionable row in the menu has matching visual
        // weight (the user reported that "Settings..." rendered with
        // a gear and "Show Dashboard" was naked text — fixed here by
        // attaching SF Symbol images to all rows).
        func makeItem(title: String, symbol: String, action: Selector, key: String) -> NSMenuItem {
            let item = NSMenuItem(title: title, action: action, keyEquivalent: key)
            item.target = self
            if let img = NSImage(systemSymbolName: symbol, accessibilityDescription: title) {
                let cfg = NSImage.SymbolConfiguration(pointSize: 13, weight: .regular)
                item.image = img.withSymbolConfiguration(cfg)
            }
            return item
        }

        menu.addItem(makeItem(title: "Show Dashboard",
                              symbol: "square.grid.2x2",
                              action: #selector(showDashboard),
                              key: "d"))
        menu.addItem(makeItem(title: "Settings…",
                              symbol: "gearshape",
                              action: #selector(openSettings),
                              key: ","))

        menu.addItem(NSMenuItem.separator())

        // Check for Updates… — the only in-UI path to trigger a Sparkle
        // check on a menubar-only app. v1.3.7 shipped with this wired to
        // SwiftUI's CommandGroup(after: .appInfo), which doesn't render
        // in LSUIElement=true apps; v1.3.8 moves it here where users
        // can actually reach it.
        menu.addItem(makeItem(title: "Check for Updates…",
                              symbol: "arrow.down.circle",
                              action: #selector(checkForUpdates),
                              key: ""))

        menu.addItem(NSMenuItem.separator())

        menu.addItem(makeItem(title: "Quit MacCrab",
                              symbol: "power",
                              action: #selector(quit),
                              key: "q"))

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
        // Using Task { @MainActor in ... } is the Swift 5.9 idiom for
        // "bounce to main later" from a nonisolated call site. Equivalent
        // semantics to the old DispatchQueue.main.async but integrates
        // with the structured concurrency world the rest of the app uses.
        Task { @MainActor [weak self] in
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
                // Tell V2DashboardShell to navigate to this specific alert.
                // V2 owns its own state via @StateObject, so we cross
                // module boundaries via NotificationCenter.
                NotificationCenter.default.post(
                    name: Notification.Name("maccrab.openAlert"),
                    object: nil,
                    userInfo: ["alertId": alert.id]
                )
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
            // Use the system's current window-background color so the popover
            // respects Light/Dark Mode. The old `.white` literal produced a
            // bright-white NSPanel over the dark desktop in Dark Mode, which
            // looked like a rendering bug to users.
            panel.backgroundColor = .windowBackgroundColor
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
        let originalAccessibilityLabel = button.accessibilityLabel() ?? "MacCrab"

        // Prepend a colored severity dot to the crab emoji so a live alert
        // is visible at a glance in the menu bar without losing the brand.
        // 🔴 for critical, 🟠 for high. Reset to the previous state after 10s.
        let prefix = severity == .critical ? "🔴" : "🟠"
        button.title = "\(prefix)🦀"
        button.setAccessibilityLabel("MacCrab — \(severity.rawValue) severity alert")

        Task { @MainActor in
            try? await Task.sleep(nanoseconds: 10_000_000_000)
            button.title = originalTitle
            button.setAccessibilityLabel(originalAccessibilityLabel)
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
                .scaledSystem(28)
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
                            .scaledSystem(9, weight: .bold)
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

