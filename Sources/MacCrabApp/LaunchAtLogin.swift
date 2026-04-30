// LaunchAtLogin.swift
// MacCrabApp
//
// Thin wrapper around macOS's ServiceManagement framework for registering
// MacCrab.app as a user login item. macOS 13+ replaced the legacy Launch
// Agents / `LSSharedFileList` approach with `SMAppService.mainApp` — one
// `.register()` call tells launchd to start MacCrab at user login, and
// `.unregister()` undoes it. No entitlement required; the user sees a
// one-time "'MacCrab' added to Login Items" notification the first time.
//
// We default to `enabled = true` for new installs because MacCrab's job
// is to protect the user — auto-starting after every login is the
// behaviour that matches the product's intent. Users who'd rather start
// it manually can flip the Settings → Startup toggle off.

import Foundation
import ServiceManagement
import os.log

enum LaunchAtLogin {

    private static let logger = Logger(subsystem: "com.maccrab.app", category: "LaunchAtLogin")

    /// v1.7.12: known paths where SMAppService might leave a `.plist`
    /// after `.unregister()`. The API removes the registration from the
    /// system database but on some macOS versions doesn't delete the
    /// file under `~/Library/LaunchAgents/`. Without this sweep, the
    /// stale file persists past `brew uninstall --cask maccrab`,
    /// past app deletion via Finder, and past a launch-at-login
    /// toggle-off in Settings — launchd silently retries to launch a
    /// missing binary on every subsequent login. Two paths because
    /// SMAppService writes either:
    ///   - `com.maccrab.app.plist`               (legacy)
    ///   - `79S425CW99.com.maccrab.app.plist`    (modern, team-id-prefixed)
    private static var launchAgentPaths: [String] {
        let dir = NSHomeDirectory() + "/Library/LaunchAgents"
        return [
            dir + "/com.maccrab.app.plist",
            dir + "/79S425CW99.com.maccrab.app.plist",
        ]
    }

    /// Sweep stale LaunchAgent files left behind by SMAppService.
    /// Called after a successful `.unregister()` and from the startup
    /// self-heal path. Best-effort: logs but doesn't propagate
    /// FileManager errors (the user can still manually `rm` the file
    /// if a permission error blocks us).
    private static func sweepStaleLaunchAgentFiles() {
        let fm = FileManager.default
        for path in launchAgentPaths where fm.fileExists(atPath: path) {
            do {
                try fm.removeItem(atPath: path)
                logger.info("Removed stale LaunchAgent file at \(path, privacy: .public)")
            } catch {
                logger.warning("Failed to remove stale LaunchAgent file at \(path, privacy: .public): \(error.localizedDescription, privacy: .public)")
            }
        }
    }

    /// True iff MacCrab.app is currently registered as a login item.
    static var isEnabled: Bool {
        SMAppService.mainApp.status == .enabled
    }

    /// Toggle the registration to the desired state. Silent no-op when the
    /// target state already matches to avoid spurious "Login Items" toasts
    /// every time the Settings view re-renders.
    static func setEnabled(_ enabled: Bool) {
        let current = SMAppService.mainApp.status
        do {
            if enabled {
                // .requiresApproval means the user enabled it in System
                // Settings → Login Items, but macOS hasn't confirmed the
                // bundle signature; treat as enabled for our purposes.
                guard current != .enabled && current != .requiresApproval else {
                    logger.debug("Login item already enabled; skipping register")
                    return
                }
                try SMAppService.mainApp.register()
                logger.info("Registered MacCrab.app as a login item")
            } else {
                guard current == .enabled || current == .requiresApproval else {
                    logger.debug("Login item already disabled; skipping unregister")
                    // Still sweep — handles the case where the API status
                    // reads "not registered" but a stale .plist file
                    // remains on disk from a prior macOS version.
                    sweepStaleLaunchAgentFiles()
                    return
                }
                try SMAppService.mainApp.unregister()
                logger.info("Unregistered MacCrab.app from login items")
                // v1.7.12: defensive sweep after unregister. SMAppService
                // doesn't always remove the underlying .plist file even
                // though .unregister() returns success.
                sweepStaleLaunchAgentFiles()
            }
        } catch {
            logger.error("Launch-at-login toggle failed: \(error.localizedDescription, privacy: .public)")
        }
    }

    /// Reconcile the @AppStorage preference with the actual registration
    /// state. Called once at app startup — handles first-run (preference
    /// default is true, so we register) and the edge case where System
    /// Settings' Login Items pane was used to toggle it outside our UI.
    ///
    /// v1.7.12: also sweeps stale LaunchAgent files when the preference
    /// is disabled — heals installs that previously had launch-at-login
    /// enabled and were then uninstalled+reinstalled or had the .plist
    /// orphaned by some other code path.
    static func reconcile(preferenceEnabled: Bool) {
        let current = SMAppService.mainApp.status
        let actuallyEnabled = (current == .enabled || current == .requiresApproval)
        if preferenceEnabled && !actuallyEnabled {
            setEnabled(true)
        } else if !preferenceEnabled && actuallyEnabled {
            setEnabled(false)
        } else if !preferenceEnabled {
            // Preference says disabled and SMAppService says disabled,
            // but a stale .plist might still exist on disk. Sweep
            // defensively — cheap (two FileManager.fileExists calls)
            // and silent when there's nothing to clean.
            sweepStaleLaunchAgentFiles()
        }
    }
}
