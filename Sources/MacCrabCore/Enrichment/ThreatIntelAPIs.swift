// ThreatIntelAPIs.swift
// MacCrabCore
//
// Unified threat intelligence API client supporting multiple vendors.
// Each vendor can be queried independently. Results are cached to avoid
// rate limiting. Degrades gracefully when API keys are missing.

import Foundation
import os.log

/// Unified threat intelligence API client supporting multiple vendors.
/// Each vendor can be queried independently. Results are cached.
public actor ThreatIntelAPIs {
    private let logger = Logger(subsystem: "com.maccrab.enrichment", category: "threat-intel-apis")
    // Per-provider sessions — each carries SPKI pins specific to that host.
    private let vtSession: URLSession = SecureURLSession.make(for: .virustotal)
    private let shodanSession: URLSession = SecureURLSession.make(for: .shodan)

    // API keys (set from config or environment)
    private var apiKeys: [String: String] = [:]

    // Result cache: "vendor:type:query" -> (result, timestamp)
    private var cache: [String: (result: LookupResult, timestamp: Date)] = [:]
    private let cacheTTL: TimeInterval = 3600  // 1 hour
    private let maxCacheSize = 5000

    // MARK: - Types

    public struct LookupResult: Sendable {
        public let vendor: String
        public let query: String
        public let isMalicious: Bool
        public let confidence: Int  // 0-100
        public let categories: [String]
        public let detail: String
        public let rawData: [String: String]

        public init(vendor: String, query: String, isMalicious: Bool,
                    confidence: Int, categories: [String],
                    detail: String, rawData: [String: String]) {
            self.vendor = vendor
            self.query = query
            self.isMalicious = isMalicious
            self.confidence = confidence
            self.categories = categories
            self.detail = detail
            self.rawData = rawData
        }
    }

    public init() {
        // Load API keys from environment or config
        let env = Foundation.ProcessInfo.processInfo.environment
        if let key = env["MACCRAB_VT_KEY"] { apiKeys["virustotal"] = key }
        if let key = env["MACCRAB_ABUSEIPDB_KEY"] { apiKeys["abuseipdb"] = key }
        if let key = env["MACCRAB_OTX_KEY"] { apiKeys["otx"] = key }
        if let key = env["MACCRAB_SHODAN_KEY"] { apiKeys["shodan"] = key }
        if let key = env["MACCRAB_URLSCAN_KEY"] { apiKeys["urlscan"] = key }
        if let key = env["MACCRAB_GREYNOISE_KEY"] { apiKeys["greynoise"] = key }
        if let key = env["MACCRAB_HIBP_KEY"] { apiKeys["hibp"] = key }
    }

    /// Set an API key programmatically.
    public func setAPIKey(vendor: String, key: String) {
        apiKeys[vendor.lowercased()] = key
    }

    /// Check which vendors are configured.
    public func configuredVendors() -> [String] {
        apiKeys.keys.sorted()
    }

    // MARK: - VirusTotal (file hash, domain, IP, URL scanning)

    public func virusTotalLookup(type: String, query: String) async -> LookupResult? {
        guard let key = apiKeys["virustotal"] else {
            logger.debug("VirusTotal: no API key configured")
            return nil
        }
        if let cached = checkCache("virustotal:\(type):\(query)") { return cached }

        let endpoint: String
        switch type {
        case "hash": endpoint = "https://www.virustotal.com/api/v3/files/\(query)"
        case "domain": endpoint = "https://www.virustotal.com/api/v3/domains/\(query)"
        case "ip": endpoint = "https://www.virustotal.com/api/v3/ip_addresses/\(query)"
        case "url":
            let urlId = Data(query.utf8).base64EncodedString()
                .replacingOccurrences(of: "=", with: "")
                .replacingOccurrences(of: "/", with: "_")
                .replacingOccurrences(of: "+", with: "-")
            endpoint = "https://www.virustotal.com/api/v3/urls/\(urlId)"
        default: return nil
        }

        guard let json = await apiRequest(url: endpoint, headers: ["x-apikey": key], session: vtSession) else {
            logger.warning("VirusTotal: API request failed for \(type):\(query)")
            return nil
        }

        let attrs = (json["data"] as? [String: Any])?["attributes"] as? [String: Any] ?? [:]
        let stats = attrs["last_analysis_stats"] as? [String: Int] ?? [:]
        let malicious = stats["malicious"] ?? 0
        let total = stats.values.reduce(0, +)
        let isMalicious = malicious > 2

        let result = LookupResult(
            vendor: "VirusTotal", query: query, isMalicious: isMalicious,
            confidence: total > 0 ? malicious * 100 / total : 0,
            categories: isMalicious ? ["malicious"] : [],
            detail: "\(malicious)/\(total) engines flagged as malicious",
            rawData: ["malicious": "\(malicious)", "total": "\(total)"]
        )
        cacheResult("virustotal:\(type):\(query)", result: result)
        return result
    }

    // MARK: - AbuseIPDB (IP reputation)

    public func abuseIPDBLookup(ip: String) async -> LookupResult? {
        guard let key = apiKeys["abuseipdb"] else {
            logger.debug("AbuseIPDB: no API key configured")
            return nil
        }
        if let cached = checkCache("abuseipdb:ip:\(ip)") { return cached }

        let endpoint = "https://api.abuseipdb.com/api/v2/check?ipAddress=\(ip)&maxAgeInDays=90"
        guard let json = await apiRequest(url: endpoint, headers: ["Key": key, "Accept": "application/json"], session: vtSession) else {
            logger.warning("AbuseIPDB: API request failed for \(ip)")
            return nil
        }

        let data = json["data"] as? [String: Any] ?? [:]
        let score = data["abuseConfidenceScore"] as? Int ?? 0
        let totalReports = data["totalReports"] as? Int ?? 0
        let isp = data["isp"] as? String ?? "Unknown"
        let country = data["countryCode"] as? String ?? "??"

        let result = LookupResult(
            vendor: "AbuseIPDB", query: ip, isMalicious: score > 50,
            confidence: score,
            categories: score > 50 ? ["abusive"] : [],
            detail: "Abuse score: \(score)%, \(totalReports) reports. ISP: \(isp) (\(country))",
            rawData: ["score": "\(score)", "reports": "\(totalReports)", "isp": isp, "country": country]
        )
        cacheResult("abuseipdb:ip:\(ip)", result: result)
        return result
    }

    // MARK: - AlienVault OTX (indicators)

    public func otxLookup(type: String, query: String) async -> LookupResult? {
        guard let key = apiKeys["otx"] else {
            logger.debug("OTX: no API key configured")
            return nil
        }
        if let cached = checkCache("otx:\(type):\(query)") { return cached }

        let section: String
        switch type {
        case "ip": section = "IPv4"
        case "domain": section = "domain"
        case "hash": section = "file"
        default: return nil
        }

        let endpoint = "https://otx.alienvault.com/api/v1/indicators/\(section)/\(query)/general"
        guard let json = await apiRequest(url: endpoint, headers: ["X-OTX-API-KEY": key], session: vtSession) else {
            logger.warning("OTX: API request failed for \(type):\(query)")
            return nil
        }

        let pulseCount = (json["pulse_info"] as? [String: Any])?["count"] as? Int ?? 0

        let result = LookupResult(
            vendor: "OTX", query: query, isMalicious: pulseCount > 0,
            confidence: min(pulseCount * 20, 100),
            categories: pulseCount > 0 ? ["threat-intel"] : [],
            detail: "Found in \(pulseCount) OTX pulse(s)",
            rawData: ["pulses": "\(pulseCount)"]
        )
        cacheResult("otx:\(type):\(query)", result: result)
        return result
    }

    // MARK: - Shodan (host intelligence)

    public func shodanLookup(ip: String) async -> LookupResult? {
        guard let key = apiKeys["shodan"] else {
            logger.debug("Shodan: no API key configured")
            return nil
        }
        if let cached = checkCache("shodan:ip:\(ip)") { return cached }

        // Shodan's REST API v1 requires the key as a query parameter (no header auth).
        // Use URLComponents to construct the URL safely rather than string interpolation,
        // and pass the key via a separate parameter so it is not embedded in logged strings.
        var components = URLComponents(string: "https://api.shodan.io/shodan/host/\(ip)")
        components?.queryItems = [URLQueryItem(name: "key", value: key)]
        guard let endpoint = components?.url?.absoluteString else { return nil }
        guard let json = await apiRequest(url: endpoint, headers: [:], session: shodanSession) else {
            logger.warning("Shodan: API request failed for \(ip)")
            return nil
        }

        let ports = (json["ports"] as? [Int])?.map(String.init).joined(separator: ", ") ?? "none"
        let os = json["os"] as? String ?? "Unknown"
        let org = json["org"] as? String ?? "Unknown"
        let vulns = json["vulns"] as? [String] ?? []

        let result = LookupResult(
            vendor: "Shodan", query: ip, isMalicious: !vulns.isEmpty,
            confidence: vulns.isEmpty ? 0 : min(vulns.count * 25, 100),
            categories: vulns.isEmpty ? [] : ["vulnerable"],
            detail: "OS: \(os), Org: \(org), Ports: \(ports), Vulns: \(vulns.count)",
            rawData: ["os": os, "org": org, "ports": ports, "vulns": "\(vulns.count)"]
        )
        cacheResult("shodan:ip:\(ip)", result: result)
        return result
    }

    // MARK: - URLScan.io (URL scanning)

    public func urlscanLookup(url: String) async -> LookupResult? {
        guard let key = apiKeys["urlscan"] else {
            logger.debug("URLScan: no API key configured")
            return nil
        }
        if let cached = checkCache("urlscan:url:\(url)") { return cached }

        // Search for existing scans
        let encoded = url.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? url
        let endpoint = "https://urlscan.io/api/v1/search/?q=page.url:\(encoded)&size=1"
        guard let json = await apiRequest(url: endpoint, headers: ["API-Key": key], session: vtSession) else {
            logger.warning("URLScan: API request failed for \(url)")
            return nil
        }

        let results = json["results"] as? [[String: Any]] ?? []
        let score = (results.first?["verdicts"] as? [String: Any])?["overall"] as? [String: Any]
        let maliciousFlag = score?["malicious"] as? Bool ?? false

        let result = LookupResult(
            vendor: "URLScan", query: url, isMalicious: maliciousFlag,
            confidence: maliciousFlag ? 80 : 0,
            categories: maliciousFlag ? ["malicious-url"] : [],
            detail: results.isEmpty ? "No scans found" : "Found \(results.count) scan(s)",
            rawData: [:]
        )
        cacheResult("urlscan:url:\(url)", result: result)
        return result
    }

    // MARK: - GreyNoise (IP noise classification)

    public func greynoiseLookup(ip: String) async -> LookupResult? {
        guard let key = apiKeys["greynoise"] else {
            logger.debug("GreyNoise: no API key configured")
            return nil
        }
        if let cached = checkCache("greynoise:ip:\(ip)") { return cached }

        let endpoint = "https://api.greynoise.io/v3/community/\(ip)"
        guard let json = await apiRequest(url: endpoint, headers: ["key": key], session: vtSession) else {
            logger.warning("GreyNoise: API request failed for \(ip)")
            return nil
        }

        let classification = json["classification"] as? String ?? "unknown"
        let noise = json["noise"] as? Bool ?? false
        let riot = json["riot"] as? Bool ?? false  // Known benign service
        let name = json["name"] as? String ?? ""

        let isMalicious = classification == "malicious"
        let result = LookupResult(
            vendor: "GreyNoise", query: ip, isMalicious: isMalicious,
            confidence: isMalicious ? 80 : (noise ? 30 : 0),
            categories: [classification],
            detail: "Classification: \(classification)\(noise ? ", internet scanner" : "")\(riot ? ", known service: \(name)" : "")",
            rawData: ["classification": classification, "noise": "\(noise)", "riot": "\(riot)"]
        )
        cacheResult("greynoise:ip:\(ip)", result: result)
        return result
    }

    // MARK: - Have I Been Pwned (breach detection)

    public func hibpLookup(email: String) async -> LookupResult? {
        guard let key = apiKeys["hibp"] else {
            logger.debug("HIBP: no API key configured")
            return nil
        }
        if let cached = checkCache("hibp:email:\(email)") { return cached }

        let encoded = email.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? email
        let endpoint = "https://haveibeenpwned.com/api/v3/breachedaccount/\(encoded)?truncateResponse=false"
        guard let rawData = await apiRequestRaw(url: endpoint, headers: ["hibp-api-key": key, "user-agent": "MacCrab"], session: vtSession) else {
            // 404 = not breached, or network error — return clean result
            let result = LookupResult(
                vendor: "HIBP", query: email, isMalicious: false,
                confidence: 0, categories: [],
                detail: "No breaches found", rawData: [:]
            )
            cacheResult("hibp:email:\(email)", result: result)
            return result
        }

        let breaches = (try? JSONSerialization.jsonObject(with: rawData) as? [[String: Any]]) ?? []
        let breachNames = breaches.compactMap { $0["Name"] as? String }.prefix(5).joined(separator: ", ")

        let result = LookupResult(
            vendor: "HIBP", query: email, isMalicious: !breaches.isEmpty,
            confidence: min(breaches.count * 20, 100),
            categories: ["breach"],
            detail: "\(breaches.count) breach(es): \(breachNames)",
            rawData: ["breachCount": "\(breaches.count)", "breaches": breachNames]
        )
        cacheResult("hibp:email:\(email)", result: result)
        return result
    }

    // MARK: - PhishTank (phishing URL check — free, no key needed)

    public func phishTankLookup(url: String) async -> LookupResult? {
        if let cached = checkCache("phishtank:url:\(url)") { return cached }

        // PhishTank has a free API (rate limited)
        let endpoint = "https://checkurl.phishtank.com/checkurl/"
        guard let requestURL = URL(string: endpoint) else { return nil }

        var request = URLRequest(url: requestURL)
        request.httpMethod = "POST"
        request.timeoutInterval = 10
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        request.setValue("MacCrab/1.0.0", forHTTPHeaderField: "User-Agent")
        let body = "url=\(url.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? url)&format=json&app_key=MacCrab"
        request.httpBody = body.data(using: .utf8)

        guard let (data, response) = try? await vtSession.data(for: request),
              let httpResponse = response as? HTTPURLResponse,
              httpResponse.statusCode == 200,
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let results = json["results"] as? [String: Any] else {
            logger.warning("PhishTank: API request failed for \(url)")
            return nil
        }

        let isPhish = results["in_database"] as? Bool ?? false
        let verified = results["verified"] as? Bool ?? false

        let result = LookupResult(
            vendor: "PhishTank", query: url, isMalicious: isPhish && verified,
            confidence: (isPhish && verified) ? 95 : (isPhish ? 60 : 0),
            categories: isPhish ? ["phishing"] : [],
            detail: isPhish ? "Confirmed phishing URL\(verified ? " (verified)" : " (unverified)")" : "Not in PhishTank database",
            rawData: ["in_database": "\(isPhish)", "verified": "\(verified)"]
        )
        cacheResult("phishtank:url:\(url)", result: result)
        return result
    }

    // MARK: - Unified Multi-Vendor Lookup

    /// Query all configured vendors for an indicator.
    public func lookupAll(type: String, query: String) async -> [LookupResult] {
        var results: [LookupResult] = []

        await withTaskGroup(of: LookupResult?.self) { group in
            switch type {
            case "ip":
                group.addTask { await self.abuseIPDBLookup(ip: query) }
                group.addTask { await self.greynoiseLookup(ip: query) }
                group.addTask { await self.shodanLookup(ip: query) }
                group.addTask { await self.otxLookup(type: "ip", query: query) }
                group.addTask { await self.virusTotalLookup(type: "ip", query: query) }
            case "domain":
                group.addTask { await self.virusTotalLookup(type: "domain", query: query) }
                group.addTask { await self.otxLookup(type: "domain", query: query) }
            case "hash":
                group.addTask { await self.virusTotalLookup(type: "hash", query: query) }
                group.addTask { await self.otxLookup(type: "hash", query: query) }
            case "url":
                group.addTask { await self.virusTotalLookup(type: "url", query: query) }
                group.addTask { await self.urlscanLookup(url: query) }
                group.addTask { await self.phishTankLookup(url: query) }
            case "email":
                group.addTask { await self.hibpLookup(email: query) }
            default: break
            }

            for await result in group {
                if let r = result { results.append(r) }
            }
        }

        return results
    }

    // MARK: - HTTP Helpers

    private nonisolated func apiRequest(url: String, headers: [String: String], session: URLSession) async -> [String: Any]? {
        guard let requestURL = URL(string: url) else { return nil }
        var request = URLRequest(url: requestURL)
        request.timeoutInterval = 10
        request.setValue("MacCrab/1.0.0", forHTTPHeaderField: "User-Agent")
        for (key, value) in headers {
            request.setValue(value, forHTTPHeaderField: key)
        }

        guard let (data, response) = try? await session.data(for: request),
              let httpResponse = response as? HTTPURLResponse,
              httpResponse.statusCode == 200 else { return nil }

        return try? JSONSerialization.jsonObject(with: data) as? [String: Any]
    }

    private nonisolated func apiRequestRaw(url: String, headers: [String: String], session: URLSession) async -> Data? {
        guard let requestURL = URL(string: url) else { return nil }
        var request = URLRequest(url: requestURL)
        request.timeoutInterval = 10
        request.setValue("MacCrab/1.0.0", forHTTPHeaderField: "User-Agent")
        for (key, value) in headers {
            request.setValue(value, forHTTPHeaderField: key)
        }

        guard let (data, response) = try? await session.data(for: request),
              let httpResponse = response as? HTTPURLResponse,
              httpResponse.statusCode == 200 else { return nil }

        return data
    }

    // MARK: - Cache

    private func checkCache(_ key: String) -> LookupResult? {
        guard let entry = cache[key],
              Date().timeIntervalSince(entry.timestamp) < cacheTTL else { return nil }
        return entry.result
    }

    private func cacheResult(_ key: String, result: LookupResult) {
        cache[key] = (result, Date())
        if cache.count > maxCacheSize {
            let oldest = cache.sorted { $0.value.timestamp < $1.value.timestamp }.prefix(100).map(\.key)
            for k in oldest { cache.removeValue(forKey: k) }
        }
    }
}
