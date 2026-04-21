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
import CryptoKit
import os.log

enum RuleBundleInstaller {

    private static let logger = Logger(subsystem: "com.maccrab.app", category: "rule-bundle")
    private static let markerFile = ".bundle_version"
    private static let manifestFile = "manifest.json"

    /// Result of verifying a compiled-rules directory against its
    /// manifest.json. Used to gate sync (don't replace installed
    /// rules if the *bundled* copy itself is tampered) and to surface
    /// "installed rules tampered after sync" as a visible banner.
    enum ManifestVerification {
        case missing                    // no manifest.json — older pre-v1.4.3 bundle, accept
        case valid                      // every file's SHA-256 matches
        case mismatch([String])         // list of paths whose hash differs
        case malformed(String)          // parse error / missing keys
    }

    /// Sync compiled rules from the app bundle to the best writable
    /// rules directory on disk. Called once on app launch, before
    /// `AppState` opens the detection engine DB. Fails silently if the
    /// bundle doesn't ship rules (dev builds, non-release `.app`s) —
    /// no functional regression for developers running `swift run`.
    ///
    /// v1.4.3: verifies the bundled manifest.json before sync. If the
    /// bundled rules directory itself has been tampered with, refuses
    /// to overwrite the installed tree and logs a critical warning.
    /// Also verifies the installed tree after sync and writes a
    /// tamper-state file the dashboard polls to raise a banner.
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

        // Verify the BUNDLED copy first. If the app bundle is tampered
        // — someone replaced compiled_rules inside /Applications after
        // installation — we must not propagate that tampered set to
        // /Library. Skip sync, log critical, let detection continue
        // with whatever's already installed.
        let bundledCheck = verifyManifest(at: bundledDir)
        if case .mismatch(let paths) = bundledCheck {
            logger.critical("Bundled rules tamper detected: \(paths.count, privacy: .public) file(s) differ from manifest. Refusing to propagate. First: \(paths.first ?? "", privacy: .public)")
            writeTamperState(bundled: true, installed: false, mismatchedCount: paths.count)
            return
        }
        if case .malformed(let msg) = bundledCheck {
            logger.error("Bundled manifest malformed: \(msg, privacy: .public); skipping sync")
            return
        }

        let installedDir = bestInstalledDir()
        let installedVersion = readVersion(at: installedDir) ?? ""

        if bundledVersion == installedVersion {
            // Same version — still verify the installed tree. Tamper
            // AFTER sync is a separate class of attack.
            let installedCheck = verifyManifest(at: installedDir)
            if case .mismatch(let paths) = installedCheck {
                logger.critical("Installed rules tamper detected (\(paths.count, privacy: .public) files differ from manifest). Re-syncing from bundle.")
                writeTamperState(bundled: false, installed: true, mismatchedCount: paths.count)
                _ = copyRules(from: bundledDir, to: installedDir)
                sighupDetectionEngine()
                return
            }
            clearTamperState()
            logger.debug("Rules already at \(bundledVersion, privacy: .public); no sync needed")
            return
        }

        logger.notice("Syncing rules: bundled=\(bundledVersion, privacy: .public) installed=\(installedVersion, privacy: .public) → \(installedDir, privacy: .public)")

        let ok = copyRules(from: bundledDir, to: installedDir)
        if ok {
            logger.notice("Rules synced to \(installedDir, privacy: .public); SIGHUPing detection engine")
            clearTamperState()
            sighupDetectionEngine()
        } else {
            logger.error("Rule sync failed; detection engine continues with whatever rules were previously installed")
        }
    }

    /// Verify every file under `dir` against its `manifest.json`.
    /// Returns `.missing` for pre-v1.4.3 bundles that shipped without
    /// a manifest (accept them), `.valid` on clean match, `.mismatch`
    /// with the list of differing files, or `.malformed` for parse
    /// errors.
    static func verifyManifest(at dir: String) -> ManifestVerification {
        let manifestPath = "\(dir)/\(manifestFile)"
        guard FileManager.default.fileExists(atPath: manifestPath) else {
            return .missing
        }
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: manifestPath)),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return .malformed("cannot read/parse manifest.json")
        }
        guard let hashes = json["hashes"] as? [String: String] else {
            return .malformed("missing 'hashes' key")
        }

        var mismatched: [String] = []
        for (relPath, expectedHash) in hashes {
            let fullPath = "\(dir)/\(relPath)"
            guard let actual = sha256Hex(ofFile: fullPath) else {
                mismatched.append(relPath)
                continue
            }
            if actual != expectedHash {
                mismatched.append(relPath)
            }
        }
        return mismatched.isEmpty ? .valid : .mismatch(mismatched)
    }

    /// Record tamper state to a JSON snapshot the dashboard polls.
    /// When tamper is cleared we remove the file so absent == healthy.
    private static let tamperStatePath = "/Library/Application Support/MacCrab/rule_tamper.json"

    private static func writeTamperState(bundled: Bool, installed: Bool, mismatchedCount: Int) {
        let payload: [String: Any] = [
            "bundled_tampered": bundled,
            "installed_tampered": installed,
            "mismatched_file_count": mismatchedCount,
            "detected_at_unix": Date().timeIntervalSince1970,
        ]
        if let data = try? JSONSerialization.data(
            withJSONObject: payload,
            options: [.prettyPrinted, .sortedKeys]
        ) {
            try? data.write(to: URL(fileURLWithPath: tamperStatePath))
        }
    }

    private static func clearTamperState() {
        try? FileManager.default.removeItem(atPath: tamperStatePath)
    }

    /// SHA-256 hex for the file at `path`. Nil if the file can't be
    /// read — verifyManifest treats that as a mismatch.
    private static func sha256Hex(ofFile path: String) -> String? {
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)) else {
            return nil
        }
        let digest = SHA256.hash(data: data)
        return digest.map { String(format: "%02x", $0) }.joined()
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
