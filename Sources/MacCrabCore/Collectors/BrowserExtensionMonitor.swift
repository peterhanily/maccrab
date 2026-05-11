// BrowserExtensionMonitor.swift
// MacCrabCore
//
// Monitors browser extension directories for new/modified extensions and flags
// suspicious ones based on dangerous permission combinations (webRequest,
// nativeMessaging, cookies, all_urls).  Covers Chrome, Firefox, Brave, Edge, Arc.

import Foundation
import os.log

/// Monitors browser extension directories for suspicious installations.
///
/// Polls the on-disk extension directories of Chromium-based browsers and Firefox,
/// parses `manifest.json` for each extension, and flags those that request
/// dangerous permission combinations.
public actor BrowserExtensionMonitor {

    private let logger = Logger(subsystem: "com.maccrab", category: "browser-extension-monitor")

    // MARK: - Types

    /// Represents a browser extension being installed or first discovered.
    public struct ExtensionEvent: Sendable {
        public let browser: String          // "chrome", "firefox", "brave", "edge", "arc"
        public let extensionId: String
        public let extensionName: String
        public let extensionPath: String
        public let permissions: [String]
        public let isNew: Bool              // First time seeing this extension
        public let isSuspicious: Bool
        public let suspicionReason: String?
        public let timestamp: Date
    }

    // MARK: - Properties

    public nonisolated let events: AsyncStream<ExtensionEvent>
    private var continuation: AsyncStream<ExtensionEvent>.Continuation?
    private var pollTask: Task<Void, Never>?
    private var knownExtensions: Set<String> = []  // extensionId set
    private let pollInterval: TimeInterval

    /// Permissions that indicate high-risk extensions.
    private static let dangerousPermissions: Set<String> = [
        "webRequest", "webRequestBlocking",        // Can intercept/modify ALL web traffic
        "cookies",                                   // Can steal auth cookies
        "clipboardRead", "clipboardWrite",          // Clipboard access
        "nativeMessaging",                           // Can spawn native processes
        "debugger",                                  // Full page debugging
        "management",                                // Can disable other extensions
        "proxy",                                     // Can redirect traffic
        "<all_urls>",                               // Access to all websites
        "http://*/*", "https://*/*",                // Same as above
        "tabs",                                      // Can see all tabs/URLs
        "history",                                   // Can read browsing history
        "downloads",                                 // Can trigger downloads
    ]

    // MARK: - Initialization

    public init(pollInterval: TimeInterval = 60) {
        self.pollInterval = pollInterval
        var capturedContinuation: AsyncStream<ExtensionEvent>.Continuation!
        self.events = AsyncStream(bufferingPolicy: .bufferingNewest(64)) { c in
            capturedContinuation = c
        }
        self.continuation = capturedContinuation
    }

    // MARK: - Lifecycle

    public func start() {
        guard pollTask == nil else { return }
        logger.info("Browser extension monitor starting (poll every \(self.pollInterval)s)")

        pollTask = Task { [weak self] in
            guard let self else { return }
            while !Task.isCancelled {
                await self.scan()
                let interval = await self.pollInterval
                // Aggressiveness 2.0: browser-extension scan is a
                // visibility feature, not time-sensitive. Slower on
                // battery is fine.
                let adjusted = PowerGate.adjustedInterval(
                    base: interval, aggressiveness: 2.0
                )
                try? await Task.sleep(nanoseconds: UInt64(adjusted * 1_000_000_000))
            }
        }
    }

    public func stop() {
        pollTask?.cancel()
        pollTask = nil
        continuation?.finish()
    }

    // MARK: - Snapshot (dashboard read path)

    /// One-shot snapshot of every browser extension currently
    /// installed. Used by the V2 dashboard's Detection › Browser
    /// tab to show the full inventory + per-extension risk
    /// summary, NOT just first-seen events. Pre-fix the monitor
    /// only emitted ExtensionEvent on first discovery via the
    /// AsyncStream — the dashboard had no way to enumerate the
    /// existing set without restarting the daemon. Now: a static
    /// `nonisolated` scan re-walks the same browser dirs and
    /// returns every manifest it can read, with permissions +
    /// risk classification.
    public struct ExtensionSnapshot: Sendable, Identifiable {
        public let id: String              // <browser>:<extensionId>
        public let browser: String         // "chrome", "firefox", "brave", ...
        public let extensionId: String
        public let extensionName: String
        public let extensionPath: String
        public let version: String?        // manifest "version", if present
        public let permissions: [String]
        public let hostPermissions: [String]
        public let isDevMode: Bool         // unpacked / loaded-from-disk
        public let dangerousPermissions: [String]
        public let riskScore: Int          // 0-100
    }

    public nonisolated static func snapshot() -> [ExtensionSnapshot] {
        let home = NSHomeDirectory()
        var out: [ExtensionSnapshot] = []
        let chromeLike: [(String, String)] = [
            ("chrome", "/Library/Application Support/Google/Chrome/Default/Extensions"),
            ("chrome", "/Library/Application Support/Google/Chrome/Profile 1/Extensions"),
            ("brave",  "/Library/Application Support/BraveSoftware/Brave-Browser/Default/Extensions"),
            ("edge",   "/Library/Application Support/Microsoft Edge/Default/Extensions"),
            ("arc",    "/Library/Application Support/Arc/User Data/Default/Extensions"),
        ]
        for (browser, suffix) in chromeLike {
            scanChromeLikeForSnapshot(at: home + suffix, browser: browser, into: &out)
        }
        scanFirefoxForSnapshot(at: home + "/Library/Application Support/Firefox/Profiles", into: &out)
        return out.sorted {
            ($0.riskScore, $0.extensionName) > ($1.riskScore, $1.extensionName)
        }
    }

    private nonisolated static func scanChromeLikeForSnapshot(
        at basePath: String, browser: String, into out: inout [ExtensionSnapshot]
    ) {
        let fm = FileManager.default
        guard let extDirs = try? fm.contentsOfDirectory(atPath: basePath) else { return }
        for extId in extDirs {
            let extPath = basePath + "/" + extId
            guard let versions = try? fm.contentsOfDirectory(atPath: extPath) else { continue }
            // Use the highest semver-ish version dir if multiple.
            let pickedVersion = versions
                .sorted(by: >)
                .first { fm.fileExists(atPath: extPath + "/" + $0 + "/manifest.json") }
            guard let v = pickedVersion else { continue }
            let manifestPath = extPath + "/" + v + "/manifest.json"
            guard let data = try? Data(contentsOf: URL(fileURLWithPath: manifestPath)),
                  let manifest = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
            else { continue }
            let name = manifest["name"] as? String ?? "Unknown"
            let version = manifest["version"] as? String
            let perms = (manifest["permissions"] as? [String]) ?? []
            let hostPerms = (manifest["host_permissions"] as? [String]) ?? []
            let allPerms = perms + hostPerms
            let dangerous = allPerms.filter { dangerousPermissions.contains($0) }
            // Heuristic risk score: 30 base for any installed extension,
            // +10 per dangerous permission, +20 if <all_urls> present,
            // +20 if nativeMessaging present, +20 if devMode/unpacked.
            // Capped at 100.
            var risk = 30 + dangerous.count * 10
            if allPerms.contains("<all_urls>") { risk += 20 }
            if allPerms.contains("nativeMessaging") { risk += 20 }
            // devMode signal: chrome-style extension dirs whose path
            // contains "Profile" but the manifest has key "key" missing
            // (unpacked) — best-effort.
            let isDev = manifest["key"] == nil && extId.count != 32
            if isDev { risk += 20 }
            risk = min(risk, 100)
            out.append(ExtensionSnapshot(
                id: "\(browser):\(extId)",
                browser: browser,
                extensionId: extId,
                extensionName: name,
                extensionPath: extPath + "/" + v,
                version: version,
                permissions: perms,
                hostPermissions: hostPerms,
                isDevMode: isDev,
                dangerousPermissions: dangerous,
                riskScore: risk
            ))
        }
    }

    private nonisolated static func scanFirefoxForSnapshot(
        at profilesPath: String, into out: inout [ExtensionSnapshot]
    ) {
        let fm = FileManager.default
        guard let profiles = try? fm.contentsOfDirectory(atPath: profilesPath) else { return }
        for profile in profiles {
            let extPath = profilesPath + "/" + profile + "/extensions"
            guard let files = try? fm.contentsOfDirectory(atPath: extPath) else { continue }
            for file in files where file.hasSuffix(".xpi") || !file.contains(".") {
                let extId = file.replacingOccurrences(of: ".xpi", with: "")
                out.append(ExtensionSnapshot(
                    id: "firefox:\(extId)",
                    browser: "firefox",
                    extensionId: extId,
                    extensionName: extId,
                    extensionPath: extPath + "/" + file,
                    version: nil,
                    permissions: [],
                    hostPermissions: [],
                    isDevMode: false,
                    dangerousPermissions: [],
                    // Without unzipping we can't see permissions; bias
                    // risk to a neutral middle so the list isn't all
                    // green just because Firefox extensions are
                    // opaque to us.
                    riskScore: 35
                ))
            }
        }
    }

    // MARK: - Scanning

    private func scan() {
        let home = NSHomeDirectory()

        // Chrome extensions
        scanChromeExtensions(
            at: home + "/Library/Application Support/Google/Chrome/Default/Extensions",
            browser: "chrome"
        )
        scanChromeExtensions(
            at: home + "/Library/Application Support/Google/Chrome/Profile 1/Extensions",
            browser: "chrome"
        )

        // Firefox extensions
        scanFirefoxExtensions(at: home + "/Library/Application Support/Firefox/Profiles")

        // Brave
        scanChromeExtensions(
            at: home + "/Library/Application Support/BraveSoftware/Brave-Browser/Default/Extensions",
            browser: "brave"
        )

        // Edge
        scanChromeExtensions(
            at: home + "/Library/Application Support/Microsoft Edge/Default/Extensions",
            browser: "edge"
        )

        // Arc
        scanChromeExtensions(
            at: home + "/Library/Application Support/Arc/User Data/Default/Extensions",
            browser: "arc"
        )
    }

    private func scanChromeExtensions(at basePath: String, browser: String) {
        let fm = FileManager.default
        guard let extDirs = try? fm.contentsOfDirectory(atPath: basePath) else { return }

        for extId in extDirs {
            let extPath = basePath + "/" + extId
            guard let versions = try? fm.contentsOfDirectory(atPath: extPath) else { continue }

            for version in versions {
                let manifestPath = extPath + "/" + version + "/manifest.json"
                guard fm.fileExists(atPath: manifestPath),
                      let data = try? Data(contentsOf: URL(fileURLWithPath: manifestPath)),
                      let manifest = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
                else { continue }

                let name = manifest["name"] as? String ?? "Unknown"
                let permissions = extractPermissions(from: manifest)
                let isNew = !knownExtensions.contains(extId)

                let dangerous = permissions.filter { Self.dangerousPermissions.contains($0) }
                let isSuspicious = dangerous.count >= 3
                    || permissions.contains("<all_urls>")
                    || permissions.contains("nativeMessaging")

                if isNew {
                    knownExtensions.insert(extId)
                    let event = ExtensionEvent(
                        browser: browser,
                        extensionId: extId,
                        extensionName: name,
                        extensionPath: extPath,
                        permissions: permissions,
                        isNew: true,
                        isSuspicious: isSuspicious,
                        suspicionReason: isSuspicious
                            ? "Dangerous permissions: \(dangerous.joined(separator: ", "))"
                            : nil,
                        timestamp: Date()
                    )
                    continuation?.yield(event)
                    logger.info("Extension discovered [\(browser)]: \(name) (\(extId)) suspicious=\(isSuspicious)")
                }
            }
        }
    }

    private func scanFirefoxExtensions(at profilesPath: String) {
        let fm = FileManager.default
        guard let profiles = try? fm.contentsOfDirectory(atPath: profilesPath) else { return }

        for profile in profiles {
            let extPath = profilesPath + "/" + profile + "/extensions"
            guard let files = try? fm.contentsOfDirectory(atPath: extPath) else { continue }

            for file in files where file.hasSuffix(".xpi") || !file.contains(".") {
                let extId = file.replacingOccurrences(of: ".xpi", with: "")
                if !knownExtensions.contains(extId) {
                    knownExtensions.insert(extId)
                    let event = ExtensionEvent(
                        browser: "firefox",
                        extensionId: extId,
                        extensionName: extId,
                        extensionPath: extPath + "/" + file,
                        permissions: [],  // Can't read .xpi without unzipping
                        isNew: true,
                        isSuspicious: false,
                        suspicionReason: nil,
                        timestamp: Date()
                    )
                    continuation?.yield(event)
                    logger.info("Extension discovered [firefox]: \(extId)")
                }
            }
        }
    }

    // MARK: - Helpers

    private func extractPermissions(from manifest: [String: Any]) -> [String] {
        var perms: [String] = []
        if let p = manifest["permissions"] as? [Any] {
            perms += p.compactMap { $0 as? String }
        }
        if let p = manifest["optional_permissions"] as? [Any] {
            perms += p.compactMap { $0 as? String }
        }
        // Manifest V3 uses host_permissions
        if let p = manifest["host_permissions"] as? [Any] {
            perms += p.compactMap { $0 as? String }
        }
        return perms
    }
}
