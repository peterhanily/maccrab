// V2SettingsBridge.swift
// Bridge from the v2 dashboard to the canonical Settings window. The
// `Settings { ... }` scene is the only preferences UI; v2 reuses it
// rather than duplicating every toggle.

import AppKit

public enum V2SettingsBridge {
    /// Open the Settings window. Pre-fix this walked the application
    /// menu looking for an item whose lowercased title contained
    /// "settings" or "preferences" — broken on every non-English
    /// macOS (German "Einstellungen", Japanese "設定", etc.). Now
    /// uses the documented AppKit selectors directly.
    @MainActor
    public static func openSettings() {
        NSApp.activate(ignoringOtherApps: true)

        // Path 1 — call AppDelegate's openSettings directly. This is
        // the most reliable path for an LSUIElement menubar app: the
        // delegate already has a working menu-walk + selector
        // fallback path wired for the menu bar's "Settings…" item.
        // Pre-fix this bridge tried `NSApp.sendAction(showSettingsWindow:)`
        // which is the documented path on macOS 14+ but silently
        // no-ops on some configurations of LSUIElement apps because
        // there's no window / responder chain to walk to the SwiftUI
        // Settings scene's first responder. Calling AppDelegate
        // directly bypasses that entirely.
        let openSel = NSSelectorFromString("openSettings")
        if let delegate = NSApp.delegate as? NSObject,
           delegate.responds(to: openSel) {
            delegate.perform(openSel)
            return
        }

        // Path 2 — modern selector for SwiftUI Settings { } scenes.
        let newSelector = Selector(("showSettingsWindow:"))
        if NSApp.sendAction(newSelector, to: nil, from: nil) { return }

        // Path 3 — pre-macOS 14 selector.
        let oldSelector = Selector(("showPreferencesWindow:"))
        if NSApp.sendAction(oldSelector, to: nil, from: nil) { return }

        // Path 4 — walk the application menu by selector identity
        // (locale-safe vs the title-text scan).
        if let appMenu = NSApp.mainMenu?.item(at: 0)?.submenu {
            for item in appMenu.items {
                if item.action == newSelector
                    || item.action == oldSelector
                    || item.action == openSel {
                    appMenu.performActionForItem(at: appMenu.index(of: item))
                    return
                }
            }
        }
    }
}
