// CertTransparency.swift
// MacCrabCore
//
// Certificate Transparency monitoring. Checks domains seen in network
// connections against CT logs to detect:
// - Connections to domains with very recently issued certificates (< 24h)
// - Connections to domains with certificates from unusual/free CAs
// - Potential typosquatting domains targeting configured watch patterns

import Foundation
import os.log

/// Monitors Certificate Transparency logs for suspicious certificates.
public actor CertTransparency {

    private let logger = Logger(subsystem: "com.maccrab", category: "cert-transparency")

    /// Cache of domain → CT check results to avoid repeated lookups.
    private var cache: [String: CTResult] = [:]
    private let maxCacheSize = 5000

    /// Domains we've already checked (avoid hammering crt.sh).
    private var checkedDomains: Set<String> = []

    /// Watch patterns for typosquatting detection (e.g., "mycompany").
    private var watchPatterns: [String] = []

    /// Recently discovered suspicious certificates.
    private var suspiciousFindings: [CTFinding] = []

    // MARK: - Types

    public struct CTResult: Sendable {
        public let domain: String
        public let certificateCount: Int
        public let oldestCertAge: TimeInterval? // seconds since oldest cert was issued
        public let newestCertAge: TimeInterval? // seconds since newest cert was issued
        public let issuers: [String]
        public let isSuspicious: Bool
        public let reason: String?
        public let checkedAt: Date
    }

    public struct CTFinding: Sendable {
        public let timestamp: Date
        public let domain: String
        public let reason: String
        public let severity: Severity
    }

    // MARK: - Configuration

    /// Free/low-trust CAs that attackers commonly use.
    private static let suspiciousCAs: Set<String> = [
        "Let's Encrypt",        // Not inherently suspicious, but used by phishing
        "ZeroSSL",
        "Buypass",
        "SSL.com",
    ]

    /// Minimum cert age (in hours) below which a cert is considered "fresh".
    private let freshCertThresholdHours: Double = 24

    // MARK: - Initialization

    public init(watchPatterns: [String] = []) {
        self.watchPatterns = watchPatterns
    }

    // MARK: - Public API

    /// Add domain patterns to watch for typosquatting.
    public func addWatchPatterns(_ patterns: [String]) {
        watchPatterns.append(contentsOf: patterns)
    }

    /// Check a domain against CT logs. Returns cached result if available.
    /// This is rate-limited and async — suitable for calling on each network event.
    public func checkDomain(_ domain: String) async -> CTResult? {
        let normalized = domain.lowercased()

        // Return cache if fresh (< 1 hour)
        if let cached = cache[normalized],
           Date().timeIntervalSince(cached.checkedAt) < 3600 {
            return cached
        }

        // Skip if already checked recently
        guard !checkedDomains.contains(normalized) else { return cache[normalized] }
        checkedDomains.insert(normalized)

        // Query crt.sh (Certificate Transparency log aggregator)
        guard let result = await queryCrtSh(domain: normalized) else { return nil }

        // Cache result
        if cache.count >= maxCacheSize {
            // Evict oldest
            if let oldest = cache.min(by: { $0.value.checkedAt < $1.value.checkedAt })?.key {
                cache.removeValue(forKey: oldest)
            }
        }
        cache[normalized] = result

        if result.isSuspicious {
            let finding = CTFinding(
                timestamp: Date(),
                domain: normalized,
                reason: result.reason ?? "Suspicious certificate",
                severity: .high
            )
            suspiciousFindings.append(finding)
            logger.warning("CT suspicious: \(normalized) — \(result.reason ?? "unknown")")
        }

        return result
    }

    /// Get all suspicious findings.
    public func getFindings() -> [CTFinding] {
        suspiciousFindings
    }

    /// Check if a domain looks like typosquatting of watched patterns.
    public func isTyposquat(_ domain: String) -> (Bool, String?) {
        let lower = domain.lowercased()
        // Strip TLD
        let parts = lower.split(separator: ".")
        guard parts.count >= 2 else { return (false, nil) }
        let baseDomain = String(parts[0])

        for pattern in watchPatterns {
            let patternLower = pattern.lowercased()

            // Check edit distance (Levenshtein)
            if baseDomain != patternLower && levenshtein(baseDomain, patternLower) <= 2 {
                return (true, "Similar to watched pattern '\(pattern)' (edit distance \(levenshtein(baseDomain, patternLower)))")
            }

            // Check for common typosquatting tricks
            if baseDomain.contains(patternLower) && baseDomain != patternLower {
                return (true, "Contains watched pattern '\(pattern)' with additions")
            }

            // Homoglyph detection (0 vs o, 1 vs l, etc.)
            let normalized = baseDomain
                .replacingOccurrences(of: "0", with: "o")
                .replacingOccurrences(of: "1", with: "l")
                .replacingOccurrences(of: "5", with: "s")
            if normalized == patternLower && baseDomain != patternLower {
                return (true, "Homoglyph of watched pattern '\(pattern)'")
            }
        }

        return (false, nil)
    }

    // MARK: - CT Log Query

    /// Query crt.sh for certificate info about a domain.
    /// crt.sh is a free Certificate Transparency log search engine.
    private nonisolated func queryCrtSh(domain: String) async -> CTResult? {
        // Use the JSON API with proper URL encoding
        var components = URLComponents(string: "https://crt.sh/")!
        components.queryItems = [
            URLQueryItem(name: "q", value: domain),
            URLQueryItem(name: "output", value: "json"),
            URLQueryItem(name: "exclude", value: "expired"),
        ]
        guard let url = components.url else { return nil }

        var request = URLRequest(url: url)
        request.timeoutInterval = 10

        do {
            let (data, response) = try await URLSession.shared.data(for: request)

            guard let http = response as? HTTPURLResponse, http.statusCode == 200 else {
                return CTResult(domain: domain, certificateCount: 0, oldestCertAge: nil, newestCertAge: nil, issuers: [], isSuspicious: false, reason: nil, checkedAt: Date())
            }

            guard let entries = try? JSONSerialization.jsonObject(with: data) as? [[String: Any]] else {
                return CTResult(domain: domain, certificateCount: 0, oldestCertAge: nil, newestCertAge: nil, issuers: [], isSuspicious: false, reason: nil, checkedAt: Date())
            }

            let now = Date()
            let dateFormatter = ISO8601DateFormatter()
            dateFormatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]

            var issuers: Set<String> = []
            var newestAge: TimeInterval?
            var oldestAge: TimeInterval?

            for entry in entries.prefix(50) { // Cap at 50 entries
                if let issuer = entry["issuer_name"] as? String {
                    // Extract CN from issuer
                    let cn = issuer.split(separator: ",")
                        .first(where: { $0.trimmingCharacters(in: .whitespaces).hasPrefix("CN=") })
                        .map { String($0.trimmingCharacters(in: .whitespaces).dropFirst(3)) }
                    if let cn { issuers.insert(cn) }
                }

                if let notBefore = entry["not_before"] as? String {
                    // Parse date: "2026-04-01T00:00:00"
                    let df = DateFormatter()
                    df.dateFormat = "yyyy-MM-dd'T'HH:mm:ss"
                    df.timeZone = TimeZone(identifier: "UTC")
                    if let date = df.date(from: notBefore) {
                        let age = now.timeIntervalSince(date)
                        if newestAge == nil || age < newestAge! { newestAge = age }
                        if oldestAge == nil || age > oldestAge! { oldestAge = age }
                    }
                }
            }

            // Determine suspiciousness
            var isSuspicious = false
            var reason: String?

            // Check for very fresh certificates
            if let age = newestAge, age < freshCertThresholdHours * 3600 {
                let hours = Int(age / 3600)
                isSuspicious = true
                reason = "Certificate issued \(hours)h ago (< \(Int(freshCertThresholdHours))h threshold)"
            }

            // Check for zero historical certificates (newly created domain)
            if entries.count <= 1 && entries.count > 0 {
                if let age = newestAge, age < 7 * 24 * 3600 {
                    isSuspicious = true
                    reason = (reason ?? "") + "; Only 1 certificate ever issued for this domain"
                }
            }

            return CTResult(
                domain: domain,
                certificateCount: entries.count,
                oldestCertAge: oldestAge,
                newestCertAge: newestAge,
                issuers: Array(issuers),
                isSuspicious: isSuspicious,
                reason: reason,
                checkedAt: now
            )

        } catch {
            return nil
        }
    }

    // MARK: - Levenshtein Distance

    private func levenshtein(_ s1: String, _ s2: String) -> Int {
        let a = Array(s1)
        let b = Array(s2)
        let m = a.count, n = b.count

        if m == 0 { return n }
        if n == 0 { return m }

        var dp = Array(repeating: Array(repeating: 0, count: n + 1), count: m + 1)
        for i in 0...m { dp[i][0] = i }
        for j in 0...n { dp[0][j] = j }

        for i in 1...m {
            for j in 1...n {
                let cost = a[i - 1] == b[j - 1] ? 0 : 1
                dp[i][j] = min(dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + cost)
            }
        }
        return dp[m][n]
    }
}
