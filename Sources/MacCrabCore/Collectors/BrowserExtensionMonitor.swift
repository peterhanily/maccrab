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
                try? await Task.sleep(nanoseconds: UInt64(interval * 1_000_000_000))
            }
        }
    }

    public func stop() {
        pollTask?.cancel()
        pollTask = nil
        continuation?.finish()
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
