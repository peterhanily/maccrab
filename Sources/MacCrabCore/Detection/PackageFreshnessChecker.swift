// PackageFreshnessChecker.swift
// MacCrabCore
//
// Supply-chain attack detector that queries package registry APIs to
// determine how recently a package was first published.  Packages
// published within the last few days (configurable, default 7) are
// flagged as "fresh" — a strong indicator of slopsquatting,
// dependency-confusion, or compromised-version attacks.
//
// Supported registries: npm, PyPI, Homebrew (formula + cask), crates.io

import Foundation
import os.log

// MARK: - PackageFreshnessChecker

/// Checks package freshness by querying registry APIs.
/// Flags packages published within a configurable threshold (default 7 days).
public actor PackageFreshnessChecker {

    private let logger = Logger(subsystem: "com.maccrab.detection", category: "package-freshness")

    // MARK: - Types

    /// Package registry identifier.
    public enum Registry: String, Sendable, CaseIterable {
        case npm = "npm"
        case pypi = "pypi"
        case homebrew = "homebrew"
        case homebrewCask = "homebrew_cask"
        case cargo = "cargo"
    }

    /// Metadata returned after querying a registry for a package.
    public struct PackageInfo: Sendable {
        public let name: String
        public let registry: Registry
        public let publishedDate: Date?
        public let ageInDays: Double?
        public let downloadCount: Int?       // Weekly downloads (npm/PyPI) or total (Cargo)
        public let isFresh: Bool             // Published within threshold
        public let isLowPopularity: Bool     // Below popularity threshold
        public let riskLevel: RiskLevel
        public let description: String
    }

    /// Risk level derived from package age and popularity.
    public enum RiskLevel: String, Sendable, Comparable {
        case safe = "safe"                   // > 30 days, popular
        case low = "low"                     // > 7 days
        case medium = "medium"               // 1-7 days old
        case high = "high"                   // < 24 hours old
        case critical = "critical"           // < 6 hours old OR < 24h + low downloads

        public var ordinal: Int {
            switch self {
            case .safe:     return 0
            case .low:      return 1
            case .medium:   return 2
            case .high:     return 3
            case .critical: return 4
            }
        }

        public static func < (lhs: RiskLevel, rhs: RiskLevel) -> Bool {
            lhs.ordinal < rhs.ordinal
        }
    }

    // MARK: - Configuration

    /// Packages published within this many days are flagged as "fresh".
    private let freshnessThresholdDays: Double

    /// Packages with fewer than this many weekly downloads are "low popularity".
    private let lowPopularityThreshold: Int

    /// Cache: "registry:name" -> PackageInfo (avoid repeated API calls).
    private var cache: [String: PackageInfo] = [:]
    private let maxCacheSize: Int = 1000

    /// Rate limiting: count of in-flight API requests.
    private var pendingRequests: Int = 0
    private let maxConcurrentRequests: Int = 3

    /// Request timeout in seconds.
    private let requestTimeout: TimeInterval = 10

    /// Shared date formatter for ISO 8601 dates.
    private static let iso8601: ISO8601DateFormatter = {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return f
    }()

    /// Fallback ISO 8601 formatter without fractional seconds.
    private static let iso8601NoFrac: ISO8601DateFormatter = {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime]
        return f
    }()

    /// User-Agent header required by some registries (crates.io).
    private static let userAgent = "MacCrab/0.5.0"

    // MARK: - Initialization

    public init(
        freshnessThresholdDays: Double = 7,
        lowPopularityThreshold: Int = 100
    ) {
        self.freshnessThresholdDays = freshnessThresholdDays
        self.lowPopularityThreshold = lowPopularityThreshold
    }

    // MARK: - Public API

    /// Check a package's freshness.  Returns a cached result if available.
    public func checkPackage(name: String, registry: Registry) async -> PackageInfo {
        let cacheKey = "\(registry.rawValue):\(name)"
        if let cached = cache[cacheKey] {
            return cached
        }

        let info: PackageInfo
        switch registry {
        case .npm:
            info = await queryNpm(name: name)
        case .pypi:
            info = await queryPyPI(name: name)
        case .homebrew:
            info = await queryHomebrew(name: name, isCask: false)
        case .homebrewCask:
            info = await queryHomebrew(name: name, isCask: true)
        case .cargo:
            info = await queryCargo(name: name)
        }

        // Evict oldest entries when cache is full.
        if cache.count >= maxCacheSize {
            // Remove a quarter of the cache (simple eviction).
            let keysToRemove = Array(cache.keys.prefix(maxCacheSize / 4))
            for key in keysToRemove {
                cache.removeValue(forKey: key)
            }
        }
        cache[cacheKey] = info

        if info.riskLevel >= .medium {
            let ageStr = info.ageInDays.map { String(format: "%.1f", $0) } ?? "unknown"
            let riskStr = info.riskLevel.rawValue
            logger.warning("Fresh package detected: \(name) (\(registry.rawValue)) age=\(ageStr) days, risk=\(riskStr)")
        }

        return info
    }

    /// Check multiple packages concurrently.
    public func checkPackages(_ packages: [(name: String, registry: Registry)]) async -> [PackageInfo] {
        await withTaskGroup(of: PackageInfo.self, returning: [PackageInfo].self) { group in
            for pkg in packages {
                group.addTask {
                    await self.checkPackage(name: pkg.name, registry: pkg.registry)
                }
            }
            var results: [PackageInfo] = []
            for await result in group {
                results.append(result)
            }
            return results
        }
    }

    /// Convenience: parse a command line and check all extracted packages.
    public func checkInstallCommand(_ commandLine: String) async -> [PackageInfo] {
        let packages = Self.parseInstallCommand(commandLine)
        guard !packages.isEmpty else { return [] }
        return await checkPackages(packages)
    }

    // MARK: - Installed Package Scanning

    /// Discover and check all installed packages from npm, pip, and Homebrew.
    /// Returns packages grouped by registry with freshness/risk assessment.
    public func scanInstalledPackages() async -> [PackageInfo] {
        var packages: [(name: String, registry: Registry)] = []

        // npm global packages
        packages.append(contentsOf: listInstalledNpm())
        // pip user packages
        packages.append(contentsOf: listInstalledPip())
        // Homebrew formulae
        packages.append(contentsOf: listInstalledBrew())

        guard !packages.isEmpty else { return [] }

        // Check in batches of 20 to avoid overwhelming APIs
        var results: [PackageInfo] = []
        for batch in stride(from: 0, to: packages.count, by: 20) {
            let end = min(batch + 20, packages.count)
            let slice = Array(packages[batch..<end])
            let batchResults = await checkPackages(slice)
            results.append(contentsOf: batchResults)
        }

        return results.sorted { $0.riskLevel.ordinal > $1.riskLevel.ordinal }
    }

    private nonisolated func listInstalledNpm() -> [(name: String, registry: Registry)] {
        guard let output = runCommand("/usr/bin/env", args: ["npm", "ls", "-g", "--depth=0", "--json"]) else { return [] }
        guard let data = output.data(using: .utf8),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let deps = json["dependencies"] as? [String: Any] else { return [] }
        return deps.keys.filter { !$0.hasPrefix("@") || $0.contains("/") }
            .prefix(100)
            .map { ($0, .npm) }
    }

    private nonisolated func listInstalledPip() -> [(name: String, registry: Registry)] {
        guard let output = runCommand("/usr/bin/env", args: ["pip3", "list", "--format=json", "--user"]) else { return [] }
        guard let data = output.data(using: .utf8),
              let arr = try? JSONSerialization.jsonObject(with: data) as? [[String: Any]] else { return [] }
        return arr.compactMap { $0["name"] as? String }
            .filter { !$0.hasPrefix("_") }
            .prefix(100)
            .map { ($0, .pypi) }
    }

    private nonisolated func listInstalledBrew() -> [(name: String, registry: Registry)] {
        guard let output = runCommand("/usr/bin/env", args: ["brew", "list", "--formula", "-1"]) else { return [] }
        return output.components(separatedBy: "\n")
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
            .prefix(100)
            .map { ($0, .homebrew) }
    }

    private nonisolated func runCommand(_ path: String, args: [String]) -> String? {
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: path)
        proc.arguments = args
        let pipe = Pipe()
        proc.standardOutput = pipe
        proc.standardError = FileHandle.nullDevice
        do {
            try proc.run()
            proc.waitUntilExit()
            guard proc.terminationStatus == 0 else { return nil }
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            return String(data: data, encoding: .utf8)
        } catch { return nil }
    }

    /// Clear the result cache.
    public func clearCache() {
        cache.removeAll()
    }

    /// Current cache size (for diagnostics).
    public func cacheCount() -> Int {
        cache.count
    }

    // MARK: - Command Line Parsing

    /// Parse a command line to extract package names and registries.
    ///
    /// Examples:
    /// - `"npm install lodash express"` -> `[("lodash", .npm), ("express", .npm)]`
    /// - `"pip install requests"` -> `[("requests", .pypi)]`
    /// - `"pip3 install -r requirements.txt"` -> `[]` (file-based install, skip)
    /// - `"brew install ffmpeg"` -> `[("ffmpeg", .homebrew)]`
    /// - `"brew install --cask firefox"` -> `[("firefox", .homebrewCask)]`
    /// - `"cargo add serde"` -> `[("serde", .cargo)]`
    public static func parseInstallCommand(_ commandLine: String) -> [(name: String, registry: Registry)] {
        let parts = commandLine.split(separator: " ").map(String.init)
        guard parts.count >= 2 else { return [] }

        let cmd = (parts[0] as NSString).lastPathComponent

        switch cmd {
        case "npm", "npx", "pnpm", "yarn":
            return parseNodeInstall(parts)
        case "pip", "pip3", "python", "python3":
            return parsePipInstall(parts)
        case "brew":
            return parseBrewInstall(parts)
        case "cargo":
            return parseCargoInstall(parts)
        default:
            return []
        }
    }

    // MARK: - Node (npm / pnpm / yarn) Parsing

    private static func parseNodeInstall(_ parts: [String]) -> [(name: String, registry: Registry)] {
        let installCmds = ["install", "i", "add"]
        guard let cmdIdx = parts.firstIndex(where: { installCmds.contains($0) }) else { return [] }

        let argStart = cmdIdx + 1
        guard argStart < parts.count else { return [] }

        return parts[argStart...].compactMap { arg -> (String, Registry)? in
            // Skip flags (--save-dev, -D, etc.)
            guard !arg.hasPrefix("-") else { return nil }

            // Handle scoped packages: @scope/name@version -> @scope/name
            let name: String
            if arg.hasPrefix("@") {
                // Scoped: "@scope/name@1.2.3" — split on the second @
                let withoutPrefix = String(arg.dropFirst())
                if let atIdx = withoutPrefix.firstIndex(of: "@") {
                    name = "@" + String(withoutPrefix[withoutPrefix.startIndex..<atIdx])
                } else {
                    name = arg
                }
            } else {
                // Unscoped: "lodash@4.17.21" -> "lodash"
                name = arg.split(separator: "@").first.map(String.init) ?? arg
            }

            guard !name.isEmpty, name != "." else { return nil }
            return (name, .npm)
        }
    }

    // MARK: - pip Parsing

    private static func parsePipInstall(_ parts: [String]) -> [(name: String, registry: Registry)] {
        guard parts.contains("install") else { return [] }
        guard let installIdx = parts.firstIndex(of: "install") else { return [] }

        let argStart = installIdx + 1
        guard argStart < parts.count else { return [] }

        // If -r or -e flags are present, skip the next argument (it's a file/path)
        var skipNext = false
        return parts[argStart...].compactMap { arg -> (String, Registry)? in
            if skipNext {
                skipNext = false
                return nil
            }
            if arg == "-r" || arg == "--requirement" || arg == "-e" || arg == "--editable" ||
               arg == "-c" || arg == "--constraint" {
                skipNext = true
                return nil
            }
            guard !arg.hasPrefix("-") else { return nil }

            // Strip version specifiers: "requests==2.31.0", "flask>=2.0", "django<4"
            let name: String
            if let range = arg.rangeOfCharacter(from: CharacterSet(charactersIn: "=><~!")) {
                name = String(arg[arg.startIndex..<range.lowerBound])
            } else {
                name = arg
            }

            guard !name.isEmpty, !name.contains("/") else { return nil }
            return (name, .pypi)
        }
    }

    // MARK: - Homebrew Parsing

    private static func parseBrewInstall(_ parts: [String]) -> [(name: String, registry: Registry)] {
        let isCask = parts.contains("--cask")
        guard parts.contains("install") else { return [] }
        guard let installIdx = parts.firstIndex(of: "install") else { return [] }

        let argStart = installIdx + 1
        guard argStart < parts.count else { return [] }

        return parts[argStart...].compactMap { arg -> (String, Registry)? in
            guard !arg.hasPrefix("-") else { return nil }
            return (arg, isCask ? .homebrewCask : .homebrew)
        }
    }

    // MARK: - Cargo Parsing

    private static func parseCargoInstall(_ parts: [String]) -> [(name: String, registry: Registry)] {
        guard parts.contains("add") || parts.contains("install") else { return [] }
        let cmdWord = parts.contains("add") ? "add" : "install"
        guard let cmdIdx = parts.firstIndex(of: cmdWord) else { return [] }

        let argStart = cmdIdx + 1
        guard argStart < parts.count else { return [] }

        // Skip flags that take a value
        var skipNext = false
        return parts[argStart...].compactMap { arg -> (String, Registry)? in
            if skipNext {
                skipNext = false
                return nil
            }
            if arg == "--vers" || arg == "--version" || arg == "--git" ||
               arg == "--path" || arg == "--branch" || arg == "--tag" || arg == "--rev" {
                skipNext = true
                return nil
            }
            guard !arg.hasPrefix("-") else { return nil }
            return (arg, .cargo)
        }
    }

    // MARK: - Registry Queries

    /// Build a URLRequest with the common User-Agent header and timeout.
    private func makeRequest(url: URL) -> URLRequest {
        var request = URLRequest(url: url, timeoutInterval: requestTimeout)
        request.setValue(Self.userAgent, forHTTPHeaderField: "User-Agent")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        return request
    }

    /// Wait until a request slot is available (rate limiting).
    private func acquireSlot() async {
        while pendingRequests >= maxConcurrentRequests {
            // Yield briefly and recheck.
            try? await Task.sleep(nanoseconds: 50_000_000) // 50ms
        }
        pendingRequests += 1
    }

    /// Release a request slot.
    private func releaseSlot() {
        pendingRequests = max(0, pendingRequests - 1)
    }

    /// Fetch JSON data from a URL and decode it.
    private func fetchJSON<T: Decodable>(url: URL, as type: T.Type) async -> T? {
        await acquireSlot()
        defer { releaseSlot() }

        let request = makeRequest(url: url)
        do {
            let (data, response) = try await URLSession.shared.data(for: request)
            guard let httpResponse = response as? HTTPURLResponse else { return nil }
            guard httpResponse.statusCode == 200 else {
                logger.debug("HTTP \(httpResponse.statusCode) for \(url.absoluteString)")
                return nil
            }
            return try JSONDecoder().decode(type, from: data)
        } catch {
            logger.debug("Failed to fetch \(url.absoluteString): \(error.localizedDescription)")
            return nil
        }
    }

    /// Parse an ISO 8601 date string, trying fractional seconds first.
    private static func parseISO8601(_ string: String) -> Date? {
        iso8601.date(from: string) ?? iso8601NoFrac.date(from: string)
    }

    // MARK: - npm

    /// npm registry response for the `time` field.
    private struct NpmRegistryResponse: Decodable {
        let time: [String: String]?  // version -> ISO 8601 timestamp
    }

    /// npm downloads API response.
    private struct NpmDownloadsResponse: Decodable {
        let downloads: Int?
    }

    private func queryNpm(name: String) async -> PackageInfo {
        // Encode scoped package names: @scope/name -> @scope%2Fname
        let encodedName = name.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? name

        // Fetch package metadata (for created date)
        guard let registryURL = URL(string: "https://registry.npmjs.org/\(encodedName)") else {
            return makeUnknownInfo(name: name, registry: .npm, description: "Invalid package name")
        }

        let registryData = await fetchJSON(url: registryURL, as: NpmRegistryResponse.self)

        var publishedDate: Date?
        if let time = registryData?.time, let created = time["created"] {
            publishedDate = Self.parseISO8601(created)
        }

        // Fetch weekly download count from the separate API
        var downloads: Int?
        if let dlURL = URL(string: "https://api.npmjs.org/downloads/point/last-week/\(encodedName)") {
            let dlData = await fetchJSON(url: dlURL, as: NpmDownloadsResponse.self)
            downloads = dlData?.downloads
        }

        // Package not found in registry
        if registryData == nil {
            return makeUnknownInfo(
                name: name,
                registry: .npm,
                description: "npm package '\(name)' not found in registry (404) — possibly unpublished or brand new"
            )
        }

        return buildPackageInfo(
            name: name,
            registry: .npm,
            publishedDate: publishedDate,
            downloads: downloads
        )
    }

    // MARK: - PyPI

    /// Partial PyPI JSON API response.
    private struct PyPIResponse: Decodable {
        let info: PyPIInfo?
        let releases: [String: [PyPIRelease]]?
    }

    private struct PyPIInfo: Decodable {
        let name: String?
        let summary: String?
    }

    private struct PyPIRelease: Decodable {
        // swiftlint:disable:next identifier_name
        let upload_time_iso_8601: String?
    }

    private func queryPyPI(name: String) async -> PackageInfo {
        guard let url = URL(string: "https://pypi.org/pypi/\(name)/json") else {
            return makeUnknownInfo(name: name, registry: .pypi, description: "Invalid package name")
        }

        guard let response = await fetchJSON(url: url, as: PyPIResponse.self) else {
            return makeUnknownInfo(
                name: name,
                registry: .pypi,
                description: "PyPI package '\(name)' not found or API error"
            )
        }

        // Find the earliest release date across all versions.
        var earliestDate: Date?
        if let releases = response.releases {
            for (_, files) in releases {
                for file in files {
                    if let ts = file.upload_time_iso_8601, let date = Self.parseISO8601(ts) {
                        if earliestDate == nil || date < earliestDate! {
                            earliestDate = date
                        }
                    }
                }
            }
        }

        // PyPI doesn't expose weekly downloads directly in the JSON API.
        // We leave downloads as nil — risk calculation handles missing data.
        return buildPackageInfo(
            name: name,
            registry: .pypi,
            publishedDate: earliestDate,
            downloads: nil
        )
    }

    // MARK: - Homebrew

    /// Partial Homebrew formula/cask API response.
    private struct HomebrewResponse: Decodable {
        let name: String?
        let analytics: HomebrewAnalytics?
    }

    private struct HomebrewAnalytics: Decodable {
        let install: HomebrewInstallAnalytics?
    }

    private struct HomebrewInstallAnalytics: Decodable {
        // The "30d" key maps to a dictionary of formula_name -> install_count.
        // We decode this manually.
        let thirtyDay: [String: Int]?

        enum CodingKeys: String, CodingKey {
            case thirtyDay = "30d"
        }
    }

    private func queryHomebrew(name: String, isCask: Bool) async -> PackageInfo {
        let registry: Registry = isCask ? .homebrewCask : .homebrew
        let endpoint = isCask ? "cask" : "formula"

        guard let url = URL(string: "https://formulae.brew.sh/api/\(endpoint)/\(name).json") else {
            return makeUnknownInfo(name: name, registry: registry, description: "Invalid package name")
        }

        guard let response = await fetchJSON(url: url, as: HomebrewResponse.self) else {
            // 404 means the formula/cask doesn't exist in the public tap.
            // This is suspicious — it might be a brand-new or fake tap.
            return PackageInfo(
                name: name,
                registry: registry,
                publishedDate: nil,
                ageInDays: nil,
                downloadCount: nil,
                isFresh: false,
                isLowPopularity: true,
                riskLevel: .critical,
                description: "Homebrew \(endpoint) '\(name)' not found in public tap — unknown or brand new"
            )
        }

        // Homebrew doesn't expose a "first published" date.  We use the
        // existence check + install analytics as a proxy.  If a formula
        // exists and has install analytics it's almost certainly established.
        var downloads: Int?
        if let analytics = response.analytics?.install?.thirtyDay {
            // Sum all install counts (keys may include variant names)
            downloads = analytics.values.reduce(0, +)
        }

        let isLowPopularity = (downloads ?? 0) < lowPopularityThreshold
        let riskLevel: RiskLevel = isLowPopularity ? .low : .safe

        return PackageInfo(
            name: name,
            registry: registry,
            publishedDate: nil,
            ageInDays: nil,
            downloadCount: downloads,
            isFresh: false,  // Can't determine freshness without a date
            isLowPopularity: isLowPopularity,
            riskLevel: riskLevel,
            description: "Homebrew \(endpoint) '\(name)' exists in public tap"
                + (downloads.map { ", \($0) installs (30d)" } ?? "")
        )
    }

    // MARK: - Cargo (crates.io)

    /// Partial crates.io API response.
    private struct CratesIOResponse: Decodable {
        // swiftlint:disable:next nesting
        struct Crate: Decodable {
            let name: String?
            // swiftlint:disable:next identifier_name
            let created_at: String?
            let downloads: Int?
            let recent_downloads: Int?
        }
        // The top-level key is "crate" (singular).
        let `crate`: Crate?

        enum CodingKeys: String, CodingKey {
            case `crate` = "crate"
        }
    }

    private func queryCargo(name: String) async -> PackageInfo {
        guard let url = URL(string: "https://crates.io/api/v1/crates/\(name)") else {
            return makeUnknownInfo(name: name, registry: .cargo, description: "Invalid crate name")
        }

        guard let response = await fetchJSON(url: url, as: CratesIOResponse.self) else {
            return makeUnknownInfo(
                name: name,
                registry: .cargo,
                description: "Crate '\(name)' not found on crates.io or API error"
            )
        }

        var publishedDate: Date?
        if let createdAt = response.crate?.created_at {
            publishedDate = Self.parseISO8601(createdAt)
        }

        let downloads = response.crate?.recent_downloads

        return buildPackageInfo(
            name: name,
            registry: .cargo,
            publishedDate: publishedDate,
            downloads: downloads
        )
    }

    // MARK: - Risk Calculation

    /// Calculate the risk level based on package age and download count.
    private func calculateRisk(ageInDays: Double?, downloads: Int?) -> RiskLevel {
        guard let age = ageInDays else {
            return .medium  // Unknown age = cautious
        }

        if age < 0.25 {  // < 6 hours
            return .critical
        }
        if age < 1.0 {  // < 24 hours
            if let dl = downloads, dl < lowPopularityThreshold {
                return .critical  // Fresh + unpopular = very suspicious
            }
            return .high
        }
        if age < freshnessThresholdDays {  // < 7 days (default)
            return .medium
        }
        if age < 30 {
            return .low
        }
        return .safe
    }

    /// Build a ``PackageInfo`` from a publish date and download count.
    private func buildPackageInfo(
        name: String,
        registry: Registry,
        publishedDate: Date?,
        downloads: Int?
    ) -> PackageInfo {
        let now = Date()
        let ageInDays: Double? = publishedDate.map { now.timeIntervalSince($0) / 86400.0 }
        let riskLevel = calculateRisk(ageInDays: ageInDays, downloads: downloads)
        let isFresh = (ageInDays ?? 0) < freshnessThresholdDays
        let isLowPopularity = (downloads ?? 0) < lowPopularityThreshold

        let description = buildDescription(
            name: name,
            registry: registry,
            ageInDays: ageInDays,
            downloads: downloads,
            riskLevel: riskLevel
        )

        return PackageInfo(
            name: name,
            registry: registry,
            publishedDate: publishedDate,
            ageInDays: ageInDays,
            downloadCount: downloads,
            isFresh: isFresh,
            isLowPopularity: isLowPopularity,
            riskLevel: riskLevel,
            description: description
        )
    }

    /// Produce an ``PackageInfo`` for packages that could not be looked up.
    private func makeUnknownInfo(name: String, registry: Registry, description: String) -> PackageInfo {
        PackageInfo(
            name: name,
            registry: registry,
            publishedDate: nil,
            ageInDays: nil,
            downloadCount: nil,
            isFresh: false,
            isLowPopularity: true,
            riskLevel: .critical,
            description: description
        )
    }

    /// Human-readable summary of the package risk assessment.
    private func buildDescription(
        name: String,
        registry: Registry,
        ageInDays: Double?,
        downloads: Int?,
        riskLevel: RiskLevel
    ) -> String {
        var parts: [String] = []
        parts.append("\(registry.rawValue) package '\(name)'")

        if let age = ageInDays {
            if age < 1.0 {
                let hours = age * 24.0
                parts.append(String(format: "first published %.1f hours ago", hours))
            } else {
                parts.append(String(format: "first published %.1f days ago", age))
            }
        } else {
            parts.append("publish date unknown")
        }

        if let dl = downloads {
            parts.append("\(dl) recent downloads")
        }

        parts.append("risk: \(riskLevel.rawValue)")
        return parts.joined(separator: ", ")
    }
}
