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
        logger.notice("syncIfNeeded invoked")
        guard let bundledDir = locateBundledRules() else {
            logger.notice("No bundled rules found — dev build or Sparkle stub; skipping sync")
            return
        }

        let bundledVersion = readVersion(at: bundledDir) ?? ""
        guard !bundledVersion.isEmpty else {
            logger.notice("Bundled rules missing \(markerFile, privacy: .public) marker; skipping (dir=\(bundledDir, privacy: .public))")
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

        // v1.12.0 RC18: ALSO compare bundled vs installed manifest.json
        // content. Pre-fix the version-only check was too coarse: every
        // 1.12.0 RC build wrote bundle_version="1.12.0", so once the
        // first RC successfully synced, every subsequent RC install
        // saw "same version" and skipped the sync — meaning Sparkle
        // updates that change the rule corpus within a patch version
        // wouldn't land either. The manifest.json is byte-different
        // across builds (it contains SHA-256 of every compiled rule),
        // so a content compare catches all real corpus changes.
        let bundledManifestData = (try? Data(
            contentsOf: URL(fileURLWithPath: bundledDir + "/\(manifestFile)")
        )) ?? Data()
        let installedManifestData = (try? Data(
            contentsOf: URL(fileURLWithPath: installedDir + "/\(manifestFile)")
        )) ?? Data()
        let manifestsMatch = !bundledManifestData.isEmpty
            && bundledManifestData == installedManifestData

        if bundledVersion == installedVersion && manifestsMatch {
            // Same version AND same manifest content. Verify the
            // installed tree against its manifest in case of tamper.
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

    /// Pick the installed rules dir we'll write to. The production
    /// sysext (running as root) only reads `/Library/Application
    /// Support/MacCrab/compiled_rules` — the user-home fallback is only
    /// useful for a `swift run maccrabd` dev daemon (NSHomeDirectory ==
    /// the daemon-uid's home). v1.12.0 fix: prior code silently fell
    /// back to user-home when the system path wasn't writable, leaving
    /// production sysext daemons running the previously-installed rule
    /// corpus indefinitely. The new behavior is loud — see
    /// `copyRulesWithElevation` below for the privileged path.
    private static func bestInstalledDir() -> String {
        return "/Library/Application Support/MacCrab/compiled_rules"
    }

    /// True when we expect to need admin authorization to write the
    /// system rules dir. The cask postflight runs as root so it never
    /// hits this; Sparkle in-place upgrades and manual drag-replace
    /// installs always hit this.
    private static func needsAuthorization(for dst: String) -> Bool {
        if dst.hasPrefix("/Library/") {
            return !FileManager.default.isWritableFile(atPath: dst)
                && !FileManager.default.isWritableFile(
                    atPath: (dst as NSString).deletingLastPathComponent
                )
        }
        return false
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
    /// linger if the new bundle removed them. v1.12.0: when the
    /// destination is the system path and we can't write to it,
    /// re-attempts via `copyRulesWithElevation` (AppleScript admin
    /// prompt). Returns false only if both unprivileged AND elevated
    /// copies fail.
    private static func copyRules(from src: String, to dst: String) -> Bool {
        let fm = FileManager.default
        if !needsAuthorization(for: dst) {
            do {
                let parent = (dst as NSString).deletingLastPathComponent
                try fm.createDirectory(atPath: parent, withIntermediateDirectories: true)
                if fm.fileExists(atPath: dst) {
                    try fm.removeItem(atPath: dst)
                }
                try fm.copyItem(atPath: src, toPath: dst)
                return true
            } catch {
                logger.error("copyRules \(src, privacy: .public) → \(dst, privacy: .public) failed unprivileged: \(error.localizedDescription, privacy: .public); attempting privileged copy")
            }
        }
        return copyRulesWithElevation(from: src, to: dst)
    }

    /// Privileged path. Prompts the user for admin credentials via
    /// AppleScript and runs the `rm -rf + cp -R + chown` sequence as
    /// root. Called when the unprivileged copy fails — which is the
    /// expected path for Sparkle in-place upgrades and drag-replace
    /// installs (the cask postflight covers the brew install path).
    /// Quoting is done in two layers: each path is shell-single-quoted via
    /// `shq` (so a quote in the path can't break out or inject), and the whole
    /// command is then escaped for AppleScript's double-quoted `do shell
    /// script` string. `src` is the .app's on-disk install path, which the
    /// user DOES control (drag-install to e.g. /Volumes/Tom's Disk/), so the
    /// shell-level escaping is load-bearing, not cosmetic.
    private static func copyRulesWithElevation(from src: String, to dst: String) -> Bool {
        let parent = (dst as NSString).deletingLastPathComponent
        // Single-line shell command: AppleScript's `do shell script`
        // interprets backslashes inside the quoted string as escapes,
        // so any literal `\;` (find -exec terminator) and any
        // continuation `\<newline>` blew up with a -2741 parse error
        // on the v1.12.0 RC10. We use `chmod -R u=rwX,go=rX` instead
        // of find+exec; the `X` form sets `x` on directories only,
        // which is exactly the dir=755 / file=644 we want. `cp -R`
        // already preserves source perms, so the chmod is belt-and-
        // suspenders — keeps the on-disk perms predictable even if a
        // future change to the .app's compiled_rules ships with
        // different bits.
        // v1.12.1 (FP fix): drop a sentinel file under the data dir at the
        // start of the elevated session and remove it at the end. The
        // sysext's SelfDefense actor reads this sentinel before firing
        // tamper alerts on deletes / renames / writes inside the data
        // dir; a present sentinel with mtime within the last 90 s
        // suppresses the alert and triggers a silent re-baseline.
        // Without this, every Sparkle/cask upgrade fires a critical
        // "compiled_rules deleted" alert because `rm -rf` on the watched
        // dir is the very thing SelfDefense was built to flag.
        // Trailing `; rm -f` (not `&&`) means we ALWAYS try to clear the
        // sentinel — and if a step fails before the cleanup, the 90 s
        // TTL still bounds the suppression window.
        let sentinel = parent + "/.maccrab_self_update_in_progress"
        // Shell-single-quote each interpolated path: wrap in '...' and turn any
        // embedded ' into '\'' so a quote in the path can't break out / inject.
        func shq(_ s: String) -> String { "'" + s.replacingOccurrences(of: "'", with: "'\\''") + "'" }
        let shell = "touch \(shq(sentinel)) && chown root:admin \(shq(sentinel)) && chmod 0644 \(shq(sentinel)) && mkdir -p \(shq(parent)) && rm -rf \(shq(dst)) && cp -R \(shq(src)) \(shq(dst)) && chown -R root:admin \(shq(dst)) && chmod -R u=rwX,go=rX \(shq(dst)); rm -f \(shq(sentinel))"
        // AppleScript's double-quoted `do shell script` string treats backslash
        // as an escape, and shq introduces backslashes ('\''), so escape `\`
        // FIRST and then `"`.
        let escaped = shell
            .replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
        let script = "do shell script \"\(escaped)\" with administrator privileges with prompt \"MacCrab needs to update its detection rules.\""
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
        task.arguments = ["-e", script]
        task.standardOutput = FileHandle.nullDevice
        let errPipe = Pipe()
        task.standardError = errPipe
        do {
            try task.run()
            task.waitUntilExit()
            if task.terminationStatus == 0 {
                logger.notice("Rules synced to \(dst, privacy: .public) via privileged copy")
                return true
            }
            let errData = (try? errPipe.fileHandleForReading.readToEnd()) ?? Data()
            let errStr = String(data: errData, encoding: .utf8) ?? "(no stderr)"
            // -128 is the AppleScript "user cancelled" exit code. Log
            // softer so a dismissed prompt doesn't look like a fault.
            if errStr.contains("(-128)") {
                logger.notice("User declined the admin prompt for rule sync; continuing with previously-installed rules")
            } else {
                logger.error("Elevated copy failed (rc=\(task.terminationStatus, privacy: .public)): \(errStr, privacy: .public)")
            }
            return false
        } catch {
            logger.error("Failed to launch osascript: \(error.localizedDescription, privacy: .public)")
            return false
        }
    }

    /// Ask the detection engine to reload its rules without a full restart.
    ///
    /// v1.17.1 fix: the release engine is the System Extension running as
    /// **root**, and this app runs as the console user — so `pkill -HUP
    /// com.maccrab.agent` EPERMs (cross-uid signal) and the SIGHUP never
    /// lands. The sync then wrote new rules to disk but the running sysext
    /// kept evaluating the OLD in-memory ruleset until its next restart —
    /// which is exactly why a fresh install/upgrade emitted alerts at the
    /// previous build's severities. Delegate to V2DaemonControl, whose
    /// PRIMARY path drops an authorized request into the privileged inbox the
    /// sysext polls (it SIGHUPs itself on receipt); `pkill -HUP maccrabd`
    /// stays only as the same-uid dev-daemon fallback.
    private static func sighupDetectionEngine() {
        _ = V2DaemonControl.reloadDetectionRules()
    }
}
