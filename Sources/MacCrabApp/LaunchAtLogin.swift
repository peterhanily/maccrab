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
                    return
                }
                try SMAppService.mainApp.unregister()
                logger.info("Unregistered MacCrab.app from login items")
            }
        } catch {
            logger.error("Launch-at-login toggle failed: \(error.localizedDescription, privacy: .public)")
        }
    }

    /// Reconcile the @AppStorage preference with the actual registration
    /// state. Called once at app startup — handles first-run (preference
    /// default is true, so we register) and the edge case where System
    /// Settings' Login Items pane was used to toggle it outside our UI.
    static func reconcile(preferenceEnabled: Bool) {
        let current = SMAppService.mainApp.status
        let actuallyEnabled = (current == .enabled || current == .requiresApproval)
        if preferenceEnabled && !actuallyEnabled {
            setEnabled(true)
        } else if !preferenceEnabled && actuallyEnabled {
            setEnabled(false)
        }
    }
}
