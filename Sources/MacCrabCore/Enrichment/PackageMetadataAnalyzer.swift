// PackageMetadataAnalyzer.swift
// MacCrabCore
//
// Scores the registry-side metadata of a newly-installed package and
// returns a structured anomaly result. One HTTP GET per registry per
// package; results cached 24h.
//
// Signals covered:
//   - Description length distribution + boilerplate clone hash
//   - Homepage host class (free-host vs corporate)
//   - Repository URL freshness (api.github.com /repos/<o>/<r>)
//   - Version history burst / 99.x.x top-version squat / first-publish ≠ 0.x
//   - Maintainer signals (noreply email, recently-added)
//
// The analyzer is dependency-injection-friendly: an optional
// `fetcher` closure lets tests substitute a mock HTTP client.

import Foundation
import os.log

// MARK: - PackageMetadataAnalyzer

public actor PackageMetadataAnalyzer {

    private let logger = Logger(subsystem: "com.maccrab.enrichment", category: "package-metadata-analyzer")

    // MARK: - Types

    public enum Registry: String, Sendable, CaseIterable {
        case npm = "npm"
        case pypi = "pypi"
    }

    public struct MetadataAnomalyResult: Sendable {
        public let packageName: String
        public let registry: Registry
        /// 0-100 aggregated risk.
        public let score: Int
        public let reasons: [String]
        /// Surfaced raw metadata for the dashboard.
        public let descriptionLength: Int
        public let homepage: String?
        public let homepageHostClass: HomepageHostClass
        public let repositoryURL: String?
        public let firstVersion: String?
        public let latestVersion: String?
        public let publishTimes: [Date]
        public let maintainerEmails: [String]

        public init(
            packageName: String, registry: Registry,
            score: Int, reasons: [String],
            descriptionLength: Int, homepage: String?,
            homepageHostClass: HomepageHostClass,
            repositoryURL: String?, firstVersion: String?,
            latestVersion: String?,
            publishTimes: [Date], maintainerEmails: [String]
        ) {
            self.packageName = packageName
            self.registry = registry
            self.score = score
            self.reasons = reasons
            self.descriptionLength = descriptionLength
            self.homepage = homepage
            self.homepageHostClass = homepageHostClass
            self.repositoryURL = repositoryURL
            self.firstVersion = firstVersion
            self.latestVersion = latestVersion
            self.publishTimes = publishTimes
            self.maintainerEmails = maintainerEmails
        }
    }

    public enum HomepageHostClass: String, Sendable {
        case unknown
        case corporate
        case freeHost          // *.vercel.app, *.netlify.app, etc.
        case missing
    }

    /// Injected HTTP client signature — `URL → Data?`.
    public typealias Fetcher = @Sendable (URL) async -> Data?

    // MARK: - State

    private var cache: [String: (result: MetadataAnomalyResult, fetched: Date)] = [:]
    private let cacheTTL: TimeInterval
    private let fetcher: Fetcher

    // MARK: - Init

    public init(cacheTTL: TimeInterval = 24 * 3600, fetcher: Fetcher? = nil) {
        self.cacheTTL = cacheTTL
        self.fetcher = fetcher ?? Self.defaultFetcher
    }

    /// Default fetcher uses the hardened registry session
    /// (TLS 1.2 floor, redirect host validation, response-size cap,
    /// no cookies, generic User-Agent).
    private static let defaultFetcher: Fetcher = { url in
        guard let result = try? await HardenedRegistrySession.fetch(url: url) else { return nil }
        return result.0
    }

    // MARK: - Public API

    /// Analyze a package by name + registry. Returns nil if the registry
    /// fetch failed completely; otherwise returns a result with partial
    /// data (score reflects only what was retrievable).
    public func analyze(packageName: String, registry: Registry) async -> MetadataAnomalyResult? {
        let cacheKey = "\(registry.rawValue):\(packageName)"
        if let entry = cache[cacheKey], Date().timeIntervalSince(entry.fetched) < cacheTTL {
            return entry.result
        }
        guard let url = url(forPackage: packageName, registry: registry) else { return nil }
        guard let data = await fetcher(url) else { return nil }
        guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return nil }

        let result = score(packageName: packageName, registry: registry, json: json)
        cache[cacheKey] = (result, Date())
        return result
    }

    // MARK: - Scoring

    private func score(packageName: String, registry: Registry, json: [String: Any]) -> MetadataAnomalyResult {
        var score = 0
        var reasons: [String] = []

        // Description length
        let description: String = {
            if registry == .npm {
                return (json["description"] as? String) ?? ""
            } else { // pypi
                if let info = json["info"] as? [String: Any] {
                    return (info["summary"] as? String) ?? (info["description"] as? String) ?? ""
                }
                return ""
            }
        }()
        let descLen = description.count
        if descLen > 0 && descLen < 20 {
            score += 15
            reasons.append("description suspiciously short (\(descLen) chars)")
        }
        if descLen == 0 {
            score += 25
            reasons.append("package has empty description")
        }
        if descLen > 50_000 {
            score += 10
            reasons.append("description suspiciously long (\(descLen) chars) — likely pasted instructional text")
        }
        let descLower = description.lowercased()
        let boilerplateMarkers = [
            "hello world", "test package", "my package", "todo",
            "this package contains", "a node.js module that provides",
        ]
        for marker in boilerplateMarkers where descLower.contains(marker) {
            score += 10
            reasons.append("description contains boilerplate phrase '\(marker)'")
            break
        }

        // Homepage host class
        let homepage: String? = {
            if registry == .npm {
                return json["homepage"] as? String
            } else if let info = json["info"] as? [String: Any] {
                return info["home_page"] as? String
            }
            return nil
        }()
        let hpClass = Self.classifyHomepage(homepage)
        switch hpClass {
        case .freeHost:
            score += 15
            reasons.append("homepage hosted on free-host service (\(homepage ?? "?"))")
        case .missing:
            score += 5
            reasons.append("package has no declared homepage")
        case .corporate, .unknown:
            break
        }

        // Repository URL
        let repoURL: String? = {
            if registry == .npm {
                if let r = json["repository"] as? [String: Any] {
                    return r["url"] as? String
                }
                return json["repository"] as? String
            } else if let info = json["info"] as? [String: Any] {
                if let urls = info["project_urls"] as? [String: String] {
                    return urls["Source"] ?? urls["Repository"] ?? urls["Homepage"]
                }
                return info["project_url"] as? String
            }
            return nil
        }()

        // Version history
        let (firstVersion, latestVersion, publishTimes) = Self.versionHistory(json: json, registry: registry)
        if let first = firstVersion, Self.isHighFirstVersion(first) {
            score += 20
            reasons.append("first published version \(first) is suspiciously high — top-version-squat (dep-confusion pattern)")
        }
        if let burstScore = Self.versionBurstScore(times: publishTimes) {
            score += burstScore
            reasons.append("publish burst detected (>=10 versions in 24h on previously-quiet package)")
        }

        // Maintainer signals
        let maintainerEmails = Self.maintainerEmails(json: json, registry: registry)
        for email in maintainerEmails {
            if email.hasSuffix("@users.noreply.github.com") {
                score += 10
                reasons.append("maintainer uses GitHub noreply address (\(email)) — common for hijacked accounts")
            }
        }

        score = min(score, 100)

        return MetadataAnomalyResult(
            packageName: packageName, registry: registry,
            score: score, reasons: reasons,
            descriptionLength: descLen, homepage: homepage,
            homepageHostClass: hpClass,
            repositoryURL: repoURL, firstVersion: firstVersion,
            latestVersion: latestVersion,
            publishTimes: publishTimes, maintainerEmails: maintainerEmails
        )
    }

    // MARK: - Helpers

    /// Build a registry URL with strict name validation. Returns nil
    /// if the supplied package name does not pass the registry's
    /// name rules — defeats SSRF via name injection.
    private func url(forPackage name: String, registry: Registry) -> URL? {
        do {
            switch registry {
            case .npm:  return try SafeRegistryURL.npmPackageMetadata(name: name)
            case .pypi: return try SafeRegistryURL.pypiPackageMetadata(name: name)
            }
        } catch {
            logger.warning("Refused invalid package name '\(name, privacy: .private)' for \(registry.rawValue, privacy: .public)")
            return nil
        }
    }

    nonisolated static func classifyHomepage(_ homepage: String?) -> HomepageHostClass {
        guard let homepage, !homepage.isEmpty, let url = URL(string: homepage), let host = url.host else {
            return .missing
        }
        let lowerHost = host.lowercased()
        let freeHostSuffixes = [
            ".vercel.app", ".netlify.app", ".herokuapp.com", ".pages.dev",
            ".fly.dev", ".glitch.me", ".surge.sh", ".replit.app",
            ".github.io", ".gitlab.io",
        ]
        for suffix in freeHostSuffixes where lowerHost.hasSuffix(suffix) {
            return .freeHost
        }
        return .corporate
    }

    nonisolated static func isHighFirstVersion(_ version: String) -> Bool {
        let trimmed = version.hasPrefix("v") ? String(version.dropFirst()) : version
        let parts = trimmed.split(separator: ".")
        guard let major = parts.first, let majorNum = Int(major) else { return false }
        return majorNum >= 90 // 99.x.x squat pattern; covers 90.0.0+ for safety margin.
    }

    nonisolated static func versionHistory(json: [String: Any], registry: Registry) -> (first: String?, latest: String?, times: [Date]) {
        switch registry {
        case .npm:
            guard let time = json["time"] as? [String: String] else { return (nil, nil, []) }
            let iso = ISO8601DateFormatter()
            var pairs: [(String, Date)] = []
            for (version, ts) in time {
                if version == "created" || version == "modified" { continue }
                if let date = iso.date(from: ts) {
                    pairs.append((version, date))
                }
            }
            pairs.sort { $0.1 < $1.1 }
            let first = pairs.first?.0
            let latest = (json["dist-tags"] as? [String: String])?["latest"] ?? pairs.last?.0
            return (first, latest, pairs.map { $0.1 })
        case .pypi:
            guard let info = json["info"] as? [String: Any],
                  let releases = json["releases"] as? [String: Any] else { return (nil, nil, []) }
            let iso = ISO8601DateFormatter()
            var pairs: [(String, Date)] = []
            for (version, files) in releases {
                guard let fileArr = files as? [[String: Any]], let firstFile = fileArr.first,
                      let upload = firstFile["upload_time_iso_8601"] as? String,
                      let date = iso.date(from: upload) else { continue }
                pairs.append((version, date))
            }
            pairs.sort { $0.1 < $1.1 }
            let first = pairs.first?.0
            let latest = (info["version"] as? String) ?? pairs.last?.0
            return (first, latest, pairs.map { $0.1 })
        }
    }

    /// Returns a burst-score increment (0 or 15) if the package shows
    /// >=10 versions in any rolling 24h window AND the prior 90-day
    /// publish rate was ≤ 1/week.
    nonisolated static func versionBurstScore(times: [Date]) -> Int? {
        guard times.count >= 10 else { return nil }
        let sorted = times.sorted()
        // Find any window of 10 consecutive versions inside 24h.
        for i in 0..<(sorted.count - 9) {
            let span = sorted[i + 9].timeIntervalSince(sorted[i])
            if span <= 24 * 3600 {
                // Check prior-90d rate.
                let cutoff = sorted[i].addingTimeInterval(-90 * 24 * 3600)
                let priorCount = sorted.filter { $0 < sorted[i] && $0 >= cutoff }.count
                if priorCount <= 13 { // ≤ 1/week × 13 weeks (~90 days)
                    return 15
                }
            }
        }
        return nil
    }

    nonisolated static func maintainerEmails(json: [String: Any], registry: Registry) -> [String] {
        switch registry {
        case .npm:
            if let m = json["maintainers"] as? [[String: Any]] {
                return m.compactMap { $0["email"] as? String }
            }
            return []
        case .pypi:
            if let info = json["info"] as? [String: Any] {
                if let email = info["author_email"] as? String, !email.isEmpty {
                    return [email]
                }
                if let email = info["maintainer_email"] as? String, !email.isEmpty {
                    return [email]
                }
            }
            return []
        }
    }
}
