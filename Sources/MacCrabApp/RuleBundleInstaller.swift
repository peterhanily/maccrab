// RuleBundleInstaller.swift
// MacCrabApp
//
// Syncs compiled detection rules from the .app bundle to the system-wide
// rules directory on launch.
//
// Problem this solves: before v1.4.2, compiled_rules lived only under
// `/Library/Application Support/MacCrab/compiled_rules/` after cask
// postflight copied them on install. `brew upgrade --cask maccrab` and
// fresh installs both re-ran the postflight, so rules stayed current
// through those channels. But **Sparkle** updates only replace the
// `.app` bundle — they never run the cask postflight. A user on v1.3.8
// who Sparkle-updated to v1.4.1 kept firing every v1.3.8-era rule-bug
// (wifi_attack_tool on spctl, invisible_unicode on logd, edr session on
// xpcproxy) because the compiler fix that landed in v1.3.11 never
// reached their disk. One v1.4.1 user in field data had 25+ false
// criticals that all traced to this.
//
// Fix: ship `compiled_rules/` inside the .app bundle at
// `MacCrab.app/Contents/Resources/compiled_rules/`. On app launch,
// compare the bundled `.bundle_version` marker to the installed one;
// if bundled is newer (or no installed version exists), copy the
// bundled tree on top of the installed tree. SIGHUP the sysext so it
// picks up the new rules immediately. Non-root app can't write to
// `/Library/Application Support/MacCrab/` directly — we use
// AuthorizationServices only if needed; otherwise we write to the
// user-home copy the detection engine falls back to.

import Foundation
import os.log

enum RuleBundleInstaller {

    private static let logger = Logger(subsystem: "com.maccrab.app", category: "rule-bundle")
    private static let markerFile = ".bundle_version"

    /// Sync compiled rules from the app bundle to the best writable
    /// rules directory on disk. Called once on app launch, before
    /// `AppState` opens the detection engine DB. Fails silently if the
    /// bundle doesn't ship rules (dev builds, non-release `.app`s) —
    /// no functional regression for developers running `swift run`.
    static func syncIfNeeded() {
        guard let bundledDir = locateBundledRules() else {
            logger.debug("No bundled rules found — dev build or Sparkle stub; skipping sync")
            return
        }

        let bundledVersion = readVersion(at: bundledDir) ?? ""
        guard !bundledVersion.isEmpty else {
            logger.debug("Bundled rules missing \(markerFile, privacy: .public) marker; skipping")
            return
        }

        let installedDir = bestInstalledDir()
        let installedVersion = readVersion(at: installedDir) ?? ""

        if bundledVersion == installedVersion {
            logger.debug("Rules already at \(bundledVersion, privacy: .public); no sync needed")
            return
        }

        logger.notice("Syncing rules: bundled=\(bundledVersion, privacy: .public) installed=\(installedVersion, privacy: .public) → \(installedDir, privacy: .public)")

        let ok = copyRules(from: bundledDir, to: installedDir)
        if ok {
            logger.notice("Rules synced to \(installedDir, privacy: .public); SIGHUPing detection engine")
            sighupDetectionEngine()
        } else {
            logger.error("Rule sync failed; detection engine continues with whatever rules were previously installed")
        }
    }

    /// Bundle rules path: Contents/Resources/compiled_rules/. Returns
    /// nil for dev builds that don't have the Resources directory.
    private static func locateBundledRules() -> String? {
        guard let url = Bundle.main.url(forResource: "compiled_rules", withExtension: nil) else {
            return nil
        }
        return url.path
    }

    /// Pick the installed rules dir we'll write to. Prefer the system
    /// path when we can write to it; otherwise fall back to user-home
    /// (which the sysext also reads). Non-root app → usually writes to
    /// user-home.
    private static func bestInstalledDir() -> String {
        let system = "/Library/Application Support/MacCrab/compiled_rules"
        if FileManager.default.isWritableFile(atPath: system) {
            return system
        }
        // Check if the parent is writable — we may need to create the dir.
        let systemParent = "/Library/Application Support/MacCrab"
        if FileManager.default.isWritableFile(atPath: systemParent) {
            return system
        }
        let home = NSHomeDirectory()
        return "\(home)/Library/Application Support/MacCrab/compiled_rules"
    }

    private static func readVersion(at dir: String) -> String? {
        let path = "\(dir)/\(markerFile)"
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)),
              let s = String(data: data, encoding: .utf8) else {
            return nil
        }
        return s.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    /// Copy the contents of `src/` into `dst/` with file-by-file
    /// overwrite. Removes `dst/` and recreates to guarantee the
    /// final tree exactly matches `src/` — no stale deprecated rules
    /// linger if the new bundle removed them.
    private static func copyRules(from src: String, to dst: String) -> Bool {
        let fm = FileManager.default
        do {
            // Ensure parent exists
            let parent = (dst as NSString).deletingLastPathComponent
            try fm.createDirectory(atPath: parent, withIntermediateDirectories: true)

            // Remove stale tree if present
            if fm.fileExists(atPath: dst) {
                try fm.removeItem(atPath: dst)
            }
            try fm.copyItem(atPath: src, toPath: dst)
            return true
        } catch {
            logger.error("copyRules \(src, privacy: .public) → \(dst, privacy: .public) failed: \(error.localizedDescription, privacy: .public)")
            return false
        }
    }

    /// Ask the detection engine to reload its rules without a full
    /// restart. Sysext runs as root (com.maccrab.agent) so this needs
    /// the sysext process to have a SIGHUP handler — which it does, per
    /// CLAUDE.md. Best-effort; if the process isn't running or pkill
    /// fails, the rules take effect on next sysext start anyway.
    private static func sighupDetectionEngine() {
        for target in ["com.maccrab.agent", "maccrabd"] {
            let p = Process()
            p.executableURL = URL(fileURLWithPath: "/usr/bin/pkill")
            p.arguments = ["-HUP", target]
            p.standardOutput = FileHandle.nullDevice
            p.standardError = FileHandle.nullDevice
            _ = try? p.run()
            p.waitUntilExit()
        }
    }
}
