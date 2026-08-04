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
        public let userId: UInt32
        public let userName: String
        public let profile: String
        public let extensionId: String
        public let version: String?
        public let extensionName: String
        public let extensionPath: String
        public let permissions: [String]
        public let isNew: Bool              // First time seeing this extension
        public let isSuspicious: Bool
        public let suspicionReason: String?
        public let timestamp: Date
    }

    /// Completeness metadata for one bounded browser-tree inventory. A partial
    /// extension array is still useful evidence, but callers must never present
    /// it as a complete inventory when an attacker-controlled directory spent
    /// the per-home dirent budget.
    public struct InventoryCoverage: Sendable, Equatable {
        public let homesScanned: Int
        public let inspectedDirectoryEntries: UInt64
        public let truncatedDirectoryCount: UInt64
        public let truncatedHomeCount: UInt64
        public let perHomeDirectoryEntryBudget: Int

        public var isComplete: Bool { truncatedHomeCount == 0 }
        public var wasTruncated: Bool { !isComplete }
    }

    /// Result-bearing replacement for the legacy array-only `snapshot()` API.
    /// `snapshot()` remains for source compatibility, while shipped consumers
    /// use this shape so a bounded partial result cannot masquerade as complete.
    public struct InventorySnapshotResult: Sendable {
        public let extensions: [ExtensionSnapshot]
        public let coverage: InventoryCoverage
    }

    /// Monotonic + last-scan diagnostics retained by the polling actor and
    /// copied into the rich heartbeat. Every total saturates at UInt64.max.
    public struct CoverageDiagnostics: Sendable, Equatable {
        public let scansTotal: UInt64
        public let truncatedScansTotal: UInt64
        public let inspectedDirectoryEntriesTotal: UInt64
        public let truncatedDirectoriesTotal: UInt64
        public let truncatedHomesTotal: UInt64
        public let lastScanCompletedAtUnix: Double?
        public let lastScanHomes: Int
        public let lastScanInspectedDirectoryEntries: UInt64
        public let lastScanTruncatedDirectoryCount: UInt64
        public let lastScanTruncatedHomeCount: UInt64
        public let perHomeDirectoryEntryBudget: Int

        public var coverageKnown: Bool { scansTotal > 0 }
        public var lastScanWasTruncated: Bool {
            coverageKnown && lastScanTruncatedHomeCount > 0
        }
        public var lastScanComplete: Bool {
            coverageKnown && !lastScanWasTruncated
        }
        public var degraded: Bool { !coverageKnown || lastScanWasTruncated }
        public var reason: String {
            if !coverageKnown { return "not_yet_scanned" }
            if lastScanWasTruncated { return "directory_budget_exhausted" }
            return ""
        }
    }

    // MARK: - Properties

    public nonisolated let events: AsyncStream<ExtensionEvent>
    private var continuation: AsyncStream<ExtensionEvent>.Continuation?
    private var pollTask: Task<Void, Never>?
    private var lifecyclePhase: CollectorLifecyclePhase = .initialized
    /// Never key an extension by id alone: ids can legitimately collide across
    /// users, browsers and profiles, and a version update must be observable.
    private var knownExtensionFamilies: Set<String> = []
    private var knownExtensionVersions: Set<String> = []
    private let pollInterval: TimeInterval
    private let homesProvider: @Sendable () -> [RealUserHome]
    private let directoryEntryBudgetPerHome: Int
    private var scansTotal: UInt64 = 0
    private var truncatedScansTotal: UInt64 = 0
    private var inspectedDirectoryEntriesTotal: UInt64 = 0
    private var truncatedDirectoriesTotal: UInt64 = 0
    private var truncatedHomesTotal: UInt64 = 0
    private var lastScanCompletedAtUnix: Double?
    private var lastScanHomes = 0
    private var lastScanInspectedDirectoryEntries: UInt64 = 0
    private var lastScanTruncatedDirectoryCount: UInt64 = 0
    private var lastScanTruncatedHomeCount: UInt64 = 0
    private var lastTruncationFaultAt: Date?

    static let maximumManifestBytes = 1 * 1024 * 1024
    static let maximumDirectoryEntriesPerHomeScan = 100_000
    private static let truncationFaultLogInterval: TimeInterval = 15 * 60

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
        self.homesProvider = { RealUserHomeResolver.all() }
        self.directoryEntryBudgetPerHome = Self.maximumDirectoryEntriesPerHomeScan
        var capturedContinuation: AsyncStream<ExtensionEvent>.Continuation!
        self.events = AsyncStream(bufferingPolicy: .bufferingNewest(64)) { c in
            capturedContinuation = c
        }
        self.continuation = capturedContinuation
    }

    init(
        pollInterval: TimeInterval = 60,
        homesProvider: @escaping @Sendable () -> [RealUserHome],
        directoryEntryBudgetPerHome: Int = BrowserExtensionMonitor.maximumDirectoryEntriesPerHomeScan
    ) {
        self.pollInterval = pollInterval
        self.homesProvider = homesProvider
        self.directoryEntryBudgetPerHome = max(1, min(directoryEntryBudgetPerHome, 1_000_000))
        var capturedContinuation: AsyncStream<ExtensionEvent>.Continuation!
        self.events = AsyncStream(bufferingPolicy: .bufferingNewest(64)) { c in
            capturedContinuation = c
        }
        self.continuation = capturedContinuation
    }

    // MARK: - Lifecycle

    public func start() {
        guard lifecyclePhase == .initialized else { return }
        lifecyclePhase = .running
        logger.info("Browser extension monitor starting (poll every \(self.pollInterval)s)")

        pollTask = Task { [weak self] in
            guard let self else { return }
            while !Task.isCancelled {
                await self.scanNow()
                let interval = self.pollInterval
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
        _ = beginStop()
    }

    @discardableResult
    public func stopAndJoin(deadline: TimeInterval = 1.0) async -> Bool {
        let task = beginStop()
        let joined = await CollectorBoundedTaskJoin.waitForAll(task.map { [$0] } ?? [], deadline: deadline)
        if joined { pollTask = nil; lifecyclePhase = .stopped }
        return joined
    }

    private func beginStop() -> Task<Void, Never>? {
        if lifecyclePhase == .stopped { return nil }
        lifecyclePhase = .stopping
        let task = pollTask
        pollTask?.cancel()
        continuation?.finish()
        continuation = nil
        return task
    }

    // MARK: - Snapshot (dashboard read path)

    /// One-shot bounded snapshot of browser extensions currently
    /// installed. The result-bearing API below carries the proof of whether the
    /// walk completed; the legacy array-only API is retained only for source
    /// compatibility and must not be used for a clean-inventory claim. Pre-fix
    /// the monitor
    /// only emitted ExtensionEvent on first discovery via the
    /// AsyncStream — the dashboard had no way to enumerate the
    /// existing set without restarting the daemon. Now: a static
    /// `nonisolated` scan re-walks the same browser dirs and
    /// returns every manifest it can read, with permissions +
    /// risk classification.
    public struct ExtensionSnapshot: Sendable, Identifiable {
        public let id: String              // <uid>:<browser>:<profile>:<extensionId>:<version>
        public let userId: UInt32
        public let userName: String
        public let profile: String
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

    @available(*, deprecated, message: "Use snapshotResult() and inspect coverage before claiming a complete inventory")
    public nonisolated static func snapshot() -> [ExtensionSnapshot] {
        snapshotResult().extensions
    }

    public nonisolated static func snapshotResult() -> InventorySnapshotResult {
        snapshotResult(
            homes: RealUserHomeResolver.all(),
            directoryEntryBudgetPerHome: maximumDirectoryEntriesPerHomeScan
        )
    }

    /// Compatibility seam for existing tests/callers that only consume rows.
    static func snapshot(homes: [RealUserHome]) -> [ExtensionSnapshot] {
        snapshotResult(
            homes: homes,
            directoryEntryBudgetPerHome: maximumDirectoryEntriesPerHomeScan
        ).extensions
    }

    /// Internal budget seam keeps adversarial padding tests cheap while the
    /// production entry point remains fixed at 100,000 inspected dirents/home.
    static func snapshotResult(
        homes: [RealUserHome],
        directoryEntryBudgetPerHome: Int
    ) -> InventorySnapshotResult {
        var out: [ExtensionSnapshot] = []
        var totalInspected: UInt64 = 0
        var totalTruncatedDirectories: UInt64 = 0
        var truncatedHomes: UInt64 = 0
        let boundedBudget = max(1, min(directoryEntryBudgetPerHome, 1_000_000))
        for home in homes {
            var directoryBudget = HomeDirectoryBudget(maximumEntries: boundedBudget)
            for location in chromeLocations(for: home, budget: &directoryBudget) {
                scanChromeLikeForSnapshot(
                    at: location.extensionsPath,
                    browser: location.browser,
                    profile: location.profile,
                    home: home,
                    budget: &directoryBudget,
                    into: &out
                )
            }
            scanFirefoxForSnapshot(
                at: home.appending("Library/Application Support/Firefox/Profiles"),
                home: home,
                budget: &directoryBudget,
                into: &out
            )
            totalInspected = saturatedAdd(totalInspected, directoryBudget.inspectedEntries)
            totalTruncatedDirectories = saturatedAdd(
                totalTruncatedDirectories,
                directoryBudget.truncatedDirectoryCount
            )
            if directoryBudget.wasTruncated {
                truncatedHomes = saturatedIncrement(truncatedHomes)
            }
        }
        let sorted = out.sorted {
            ($0.riskScore, $0.userName, $0.extensionName, $0.id)
                > ($1.riskScore, $1.userName, $1.extensionName, $1.id)
        }
        return InventorySnapshotResult(
            extensions: sorted,
            coverage: InventoryCoverage(
                homesScanned: homes.count,
                inspectedDirectoryEntries: totalInspected,
                truncatedDirectoryCount: totalTruncatedDirectories,
                truncatedHomeCount: truncatedHomes,
                perHomeDirectoryEntryBudget: boundedBudget
            )
        )
    }

    private struct ChromeLocation {
        let browser: String
        let profile: String
        let extensionsPath: String
    }

    /// One global inspected-dirent allowance for every browser tree belonging
    /// to one home. There are intentionally no profile/extension/version caps:
    /// a same-UID adversary must spend the full home budget to hide a sibling,
    /// and spending it makes the inventory explicitly degraded.
    private struct HomeDirectoryBudget {
        private(set) var remainingEntries: Int
        private(set) var inspectedEntries: UInt64 = 0
        private(set) var truncatedDirectoryCount: UInt64 = 0
        private(set) var wasTruncated = false

        init(maximumEntries: Int) {
            remainingEntries = max(1, min(maximumEntries, 1_000_000))
        }

        mutating func consume(_ snapshot: BoundedDirectoryLister.Snapshot) {
            remainingEntries = max(0, remainingEntries - snapshot.inspectedEntryCount)
            inspectedEntries = BrowserExtensionMonitor.saturatedAdd(
                inspectedEntries,
                UInt64(snapshot.inspectedEntryCount)
            )
            if snapshot.wasTruncated {
                wasTruncated = true
                truncatedDirectoryCount = BrowserExtensionMonitor.saturatedIncrement(
                    truncatedDirectoryCount
                )
            }
        }
    }

    private nonisolated static func chromeLocations(
        for home: RealUserHome,
        budget: inout HomeDirectoryBudget
    ) -> [ChromeLocation] {
        let bases: [(browser: String, relativePath: String)] = [
            ("chrome", "Library/Application Support/Google/Chrome"),
            ("brave", "Library/Application Support/BraveSoftware/Brave-Browser"),
            ("edge", "Library/Application Support/Microsoft Edge"),
            ("arc", "Library/Application Support/Arc/User Data"),
        ]
        var result: [ChromeLocation] = []
        for base in bases {
            let basePath = home.appending(base.relativePath)
            let profiles = userEntries(
                at: basePath,
                home: home,
                kinds: [.directory],
                budget: &budget
            )
            for profile in profiles.map(\.name) {
                let extensions = basePath + "/" + profile + "/Extensions"
                guard BoundedDirectoryLister.isDirectory(
                    at: extensions,
                    expectedOwnerUID: home.userID
                ) else { continue }
                result.append(ChromeLocation(
                    browser: base.browser,
                    profile: profile,
                    extensionsPath: extensions
                ))
            }
        }
        return result
    }

    private nonisolated static func scanChromeLikeForSnapshot(
        at basePath: String,
        browser: String,
        profile: String,
        home: RealUserHome,
        budget: inout HomeDirectoryBudget,
        into out: inout [ExtensionSnapshot]
    ) {
        let extDirs = userEntries(
            at: basePath,
            home: home,
            kinds: [.directory],
            budget: &budget
        )
        for extId in extDirs.map(\.name) {
            let extPath = basePath + "/" + extId
            let versions = userEntries(
                at: extPath,
                home: home,
                kinds: [.directory],
                budget: &budget
            ).map(\.name)
            // Use the highest semver-ish version dir if multiple.
            let candidates = versions.sorted(by: >)
            var loaded: (String, [String: Any])?
            for candidate in candidates {
                let manifestPath = extPath + "/" + candidate + "/manifest.json"
                if let manifest = readManifest(at: manifestPath, ownerUID: home.userID) {
                    loaded = (candidate, manifest)
                    break
                }
            }
            guard let loaded else { continue }
            let (v, manifest) = loaded
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
                id: identityKey(
                    home: home,
                    browser: browser,
                    profile: profile,
                    extensionID: extId,
                    version: version ?? v
                ),
                userId: home.userID,
                userName: home.userName,
                profile: profile,
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
        at profilesPath: String,
        home: RealUserHome,
        budget: inout HomeDirectoryBudget,
        into out: inout [ExtensionSnapshot]
    ) {
        let profiles = userEntries(
            at: profilesPath,
            home: home,
            kinds: [.directory],
            budget: &budget
        )
        for profile in profiles.map(\.name) {
            let extPath = profilesPath + "/" + profile + "/extensions"
            let files = userEntries(
                at: extPath,
                home: home,
                kinds: [.regularFile, .directory],
                budget: &budget
            )
            for file in files.map(\.name) where file.hasSuffix(".xpi") || !file.contains(".") {
                let extId = file.replacingOccurrences(of: ".xpi", with: "")
                out.append(ExtensionSnapshot(
                    id: identityKey(
                        home: home,
                        browser: "firefox",
                        profile: profile,
                        extensionID: extId,
                        version: "unknown"
                    ),
                    userId: home.userID,
                    userName: home.userName,
                    profile: profile,
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

    /// Run one bounded inventory pass. Internal so adversarial tests can drive a
    /// deterministic scan without starting/sleeping the polling task.
    func scanNow() {
        let homes = homesProvider()
        var totalInspected: UInt64 = 0
        var totalTruncatedDirectories: UInt64 = 0
        var truncatedHomes: UInt64 = 0
        for home in homes {
            var directoryBudget = HomeDirectoryBudget(
                maximumEntries: directoryEntryBudgetPerHome
            )
            for location in Self.chromeLocations(for: home, budget: &directoryBudget) {
                scanChromeExtensions(
                    at: location.extensionsPath,
                    browser: location.browser,
                    profile: location.profile,
                    home: home,
                    budget: &directoryBudget
                )
            }
            scanFirefoxExtensions(
                at: home.appending("Library/Application Support/Firefox/Profiles"),
                home: home,
                budget: &directoryBudget
            )
            totalInspected = Self.saturatedAdd(
                totalInspected,
                directoryBudget.inspectedEntries
            )
            totalTruncatedDirectories = Self.saturatedAdd(
                totalTruncatedDirectories,
                directoryBudget.truncatedDirectoryCount
            )
            if directoryBudget.wasTruncated {
                truncatedHomes = Self.saturatedIncrement(truncatedHomes)
            }
        }

        let previousScanWasTruncated = lastScanTruncatedHomeCount > 0
        scansTotal = Self.saturatedIncrement(scansTotal)
        inspectedDirectoryEntriesTotal = Self.saturatedAdd(
            inspectedDirectoryEntriesTotal,
            totalInspected
        )
        truncatedDirectoriesTotal = Self.saturatedAdd(
            truncatedDirectoriesTotal,
            totalTruncatedDirectories
        )
        truncatedHomesTotal = Self.saturatedAdd(truncatedHomesTotal, truncatedHomes)
        if truncatedHomes > 0 {
            truncatedScansTotal = Self.saturatedIncrement(truncatedScansTotal)
        }
        let now = Date()
        lastScanCompletedAtUnix = now.timeIntervalSince1970
        lastScanHomes = homes.count
        lastScanInspectedDirectoryEntries = totalInspected
        lastScanTruncatedDirectoryCount = totalTruncatedDirectories
        lastScanTruncatedHomeCount = truncatedHomes

        if truncatedHomes > 0,
           lastTruncationFaultAt.map({
               now.timeIntervalSince($0) >= Self.truncationFaultLogInterval
           }) ?? true {
            lastTruncationFaultAt = now
            logger.fault(
                "Browser extension inventory DEGRADED: bounded scan exhausted the per-home dirent budget; partial rows must not be treated as complete (homes=\(homes.count, privacy: .public) truncated_homes=\(truncatedHomes, privacy: .public) inspected=\(totalInspected, privacy: .public) budget_per_home=\(self.directoryEntryBudgetPerHome, privacy: .public))"
            )
        } else if previousScanWasTruncated && truncatedHomes == 0 {
            logger.notice("Browser extension inventory coverage recovered; latest bounded scan completed")
        }
    }

    /// Snapshot retained independently of extension first-seen state. Heartbeat
    /// consumers can therefore distinguish a complete quiet scan from a partial
    /// quiet scan where a malicious target may sit beyond the bounded budget.
    public func coverageDiagnostics() -> CoverageDiagnostics {
        CoverageDiagnostics(
            scansTotal: scansTotal,
            truncatedScansTotal: truncatedScansTotal,
            inspectedDirectoryEntriesTotal: inspectedDirectoryEntriesTotal,
            truncatedDirectoriesTotal: truncatedDirectoriesTotal,
            truncatedHomesTotal: truncatedHomesTotal,
            lastScanCompletedAtUnix: lastScanCompletedAtUnix,
            lastScanHomes: lastScanHomes,
            lastScanInspectedDirectoryEntries: lastScanInspectedDirectoryEntries,
            lastScanTruncatedDirectoryCount: lastScanTruncatedDirectoryCount,
            lastScanTruncatedHomeCount: lastScanTruncatedHomeCount,
            perHomeDirectoryEntryBudget: directoryEntryBudgetPerHome
        )
    }

    private func scanChromeExtensions(
        at basePath: String,
        browser: String,
        profile: String,
        home: RealUserHome,
        budget: inout HomeDirectoryBudget
    ) {
        let extDirs = Self.userEntries(
            at: basePath,
            home: home,
            kinds: [.directory],
            budget: &budget
        )

        for extId in extDirs.map(\.name) {
            let extPath = basePath + "/" + extId
            let versions = Self.userEntries(
                at: extPath,
                home: home,
                kinds: [.directory],
                budget: &budget
            )

            for version in versions.map(\.name) {
                let manifestPath = extPath + "/" + version + "/manifest.json"
                guard let manifest = Self.readManifest(
                    at: manifestPath,
                    ownerUID: home.userID
                ) else { continue }

                let name = manifest["name"] as? String ?? "Unknown"
                let permissions = extractPermissions(from: manifest)
                let manifestVersion = manifest["version"] as? String ?? version
                let familyKey = Self.identityKey(
                    home: home,
                    browser: browser,
                    profile: profile,
                    extensionID: extId,
                    version: nil
                )
                let versionKey = Self.identityKey(
                    home: home,
                    browser: browser,
                    profile: profile,
                    extensionID: extId,
                    version: manifestVersion
                )
                let isNew = !knownExtensionFamilies.contains(familyKey)

                let dangerous = permissions.filter { Self.dangerousPermissions.contains($0) }
                let isSuspicious = dangerous.count >= 3
                    || permissions.contains("<all_urls>")
                    || permissions.contains("nativeMessaging")

                if !knownExtensionVersions.contains(versionKey) {
                    knownExtensionFamilies.insert(familyKey)
                    knownExtensionVersions.insert(versionKey)
                    let event = ExtensionEvent(
                        browser: browser,
                        userId: home.userID,
                        userName: home.userName,
                        profile: profile,
                        extensionId: extId,
                        version: manifestVersion,
                        extensionName: name,
                        extensionPath: extPath,
                        permissions: permissions,
                        isNew: isNew,
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

    private func scanFirefoxExtensions(
        at profilesPath: String,
        home: RealUserHome,
        budget: inout HomeDirectoryBudget
    ) {
        let profiles = Self.userEntries(
            at: profilesPath,
            home: home,
            kinds: [.directory],
            budget: &budget
        )

        for profile in profiles.map(\.name) {
            let extPath = profilesPath + "/" + profile + "/extensions"
            let files = Self.userEntries(
                at: extPath,
                home: home,
                kinds: [.regularFile, .directory],
                budget: &budget
            )

            for file in files.map(\.name) where file.hasSuffix(".xpi") || !file.contains(".") {
                let extId = file.replacingOccurrences(of: ".xpi", with: "")
                let versionKey = Self.identityKey(
                    home: home,
                    browser: "firefox",
                    profile: profile,
                    extensionID: extId,
                    version: "unknown"
                )
                if !knownExtensionVersions.contains(versionKey) {
                    knownExtensionFamilies.insert(Self.identityKey(
                        home: home,
                        browser: "firefox",
                        profile: profile,
                        extensionID: extId,
                        version: nil
                    ))
                    knownExtensionVersions.insert(versionKey)
                    let event = ExtensionEvent(
                        browser: "firefox",
                        userId: home.userID,
                        userName: home.userName,
                        profile: profile,
                        extensionId: extId,
                        version: nil,
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

    private nonisolated static func userEntries(
        at path: String,
        home: RealUserHome,
        kinds: Set<BoundedDirectoryLister.EntryKind>,
        budget: inout HomeDirectoryBudget
    ) -> [BoundedDirectoryLister.Entry] {
        guard budget.remainingEntries > 0 else { return [] }
        guard let snapshot = BoundedDirectoryLister.list(
            at: path,
            maximumEntries: budget.remainingEntries,
            expectedOwnerUID: home.userID
        ) else { return [] }
        // Consume partial evidence, but propagate the truncation into both the
        // actor heartbeat diagnostics and the static result-bearing API.
        budget.consume(snapshot)
        return snapshot.entries.filter {
            $0.ownerUID == home.userID && kinds.contains($0.kind)
        }
    }

    nonisolated static func saturatedAdd(_ lhs: UInt64, _ rhs: UInt64) -> UInt64 {
        let (sum, overflow) = lhs.addingReportingOverflow(rhs)
        return overflow ? .max : sum
    }

    nonisolated static func saturatedIncrement(_ value: UInt64) -> UInt64 {
        saturatedAdd(value, 1)
    }

    private nonisolated static func readManifest(
        at path: String,
        ownerUID: UInt32
    ) -> [String: Any]? {
        guard case .success(let snapshot) = BoundedRegularFileReader.readOutcome(
                  at: path,
                  maximumBytes: maximumManifestBytes
              ), snapshot.ownerUID == ownerUID,
              let manifest = try? JSONSerialization.jsonObject(with: snapshot.data) as? [String: Any] else {
            return nil
        }
        return manifest
    }

    private nonisolated static func identityKey(
        home: RealUserHome,
        browser: String,
        profile: String,
        extensionID: String,
        version: String?
    ) -> String {
        [
            String(home.userID), browser, profile, extensionID,
            version ?? "<family>",
        ].joined(separator: ":")
    }

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
