// ThreatIntelFeed.swift
// MacCrabCore
//
// Downloads and caches indicators of compromise (IOCs) from open threat
// intelligence feeds. Checks processes, files, and network connections
// against known-bad hashes, IPs, and domains.

import Foundation
import os.log

/// Manages threat intelligence feeds and IOC lookups.
///
/// Supported feeds:
/// - abuse.ch URLhaus (malicious URLs/domains)
/// - abuse.ch MalwareBazaar (malicious file hashes)
/// - abuse.ch Feodo Tracker (C2 IP addresses)
/// - Custom IOC lists (user-provided)
public actor ThreatIntelFeed {

    private let logger = Logger(subsystem: "com.maccrab", category: "threat-intel")

    // MARK: - IOC Storage

    /// Known-bad SHA-256 file hashes.
    private var maliciousHashes: Set<String> = []

    /// Known-bad IP addresses (C2, malware distribution).
    private var maliciousIPs: Set<String> = []

    /// Known-bad domains.
    private var maliciousDomains: Set<String> = []

    /// Known-bad URLs.
    private var maliciousURLs: Set<String> = []

    /// When feeds were last updated.
    private var lastUpdate: Date?

    /// Directory for cached feed data.
    private let cacheDir: String

    /// Update interval (default: 4 hours).
    private let updateInterval: TimeInterval

    /// Whether auto-update is running.
    private var isRunning = false

    // MARK: - Initialization

    public init(cacheDir: String? = nil, updateInterval: TimeInterval = 4 * 3600) {
        let dir = cacheDir ?? {
            let appSupport = FileManager.default.urls(
                for: .applicationSupportDirectory,
                in: .userDomainMask
            ).first ?? URL(fileURLWithPath: NSTemporaryDirectory())
            return appSupport.appendingPathComponent("MacCrab/threat_intel").path
        }()
        self.cacheDir = dir
        self.updateInterval = updateInterval
        try? FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
    }

    // MARK: - Public API

    /// Start auto-updating feeds in the background.
    public func start() {
        isRunning = true

        // Load cached data first (instant, no network)
        loadCachedFeeds()

        // Then update from network
        Task {
            await updateAllFeeds()

            // Schedule periodic updates
            while isRunning {
                try? await Task.sleep(nanoseconds: UInt64(updateInterval * 1_000_000_000))
                guard isRunning else { break }
                await updateAllFeeds()
            }
        }
    }

    /// Stop auto-updating.
    public func stop() {
        isRunning = false
    }

    /// Check if a SHA-256 hash is known-malicious.
    public func isHashMalicious(_ hash: String) -> Bool {
        maliciousHashes.contains(hash.lowercased())
    }

    /// Check if an IP address is known-malicious.
    public func isIPMalicious(_ ip: String) -> Bool {
        maliciousIPs.contains(ip)
    }

    /// Check if a domain is known-malicious.
    public func isDomainMalicious(_ domain: String) -> Bool {
        let lower = domain.lowercased()
        // Check exact match and parent domains
        if maliciousDomains.contains(lower) { return true }
        let parts = lower.split(separator: ".")
        for i in 1..<parts.count {
            let parent = parts[i...].joined(separator: ".")
            if maliciousDomains.contains(parent) { return true }
        }
        return false
    }

    /// Check a URL against known-malicious URLs.
    public func isURLMalicious(_ url: String) -> Bool {
        let lower = url.lowercased()
        return maliciousURLs.contains { lower.contains($0) }
    }

    /// Get statistics about loaded IOCs.
    public func stats() -> (hashes: Int, ips: Int, domains: Int, urls: Int, lastUpdate: Date?) {
        (maliciousHashes.count, maliciousIPs.count, maliciousDomains.count, maliciousURLs.count, lastUpdate)
    }

    /// Add custom IOCs (user-provided).
    public func addCustomIOCs(hashes: [String] = [], ips: [String] = [], domains: [String] = []) {
        for h in hashes { maliciousHashes.insert(h.lowercased()) }
        for ip in ips { maliciousIPs.insert(ip) }
        for d in domains { maliciousDomains.insert(d.lowercased()) }
    }

    /// Load IOCs from a custom file (one per line, # comments).
    public func loadCustomFile(path: String, type: IOCType) throws {
        let content = try String(contentsOfFile: path, encoding: .utf8)
        let lines = content.split(separator: "\n")
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty && !$0.hasPrefix("#") }

        switch type {
        case .hash:   for l in lines { maliciousHashes.insert(l.lowercased()) }
        case .ip:     for l in lines { maliciousIPs.insert(l) }
        case .domain: for l in lines { maliciousDomains.insert(l.lowercased()) }
        case .url:    for l in lines { maliciousURLs.insert(l.lowercased()) }
        }

        logger.info("Loaded \(lines.count) custom \(type.rawValue) IOCs from \(path)")
    }

    public enum IOCType: String {
        case hash, ip, domain, url
    }

    // MARK: - Feed Updates

    private func updateAllFeeds() async {
        logger.info("Updating threat intelligence feeds...")
        var totalNew = 0

        totalNew += await updateFeodoTracker()
        totalNew += await updateURLhaus()
        totalNew += await updateMalwareBazaar()

        // Load any custom IOC files in the cache directory
        loadCustomIOCFiles()

        lastUpdate = Date()
        saveCache()

        logger.info("Threat intel update complete: \(totalNew) new IOCs. Total: \(self.maliciousHashes.count) hashes, \(self.maliciousIPs.count) IPs, \(self.maliciousDomains.count) domains")
        print("Threat intel: \(maliciousHashes.count) hashes, \(maliciousIPs.count) IPs, \(maliciousDomains.count) domains (updated \(totalNew) new)")
    }

    /// Feodo Tracker — C2 botnet IP addresses.
    /// https://feodotracker.abuse.ch/downloads/ipblocklist.csv
    private func updateFeodoTracker() async -> Int {
        let url = "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt"
        guard let lines = await fetchLines(url: url) else { return 0 }

        var added = 0
        for line in lines {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.isEmpty || trimmed.hasPrefix("#") { continue }
            // Each line is just an IP
            if maliciousIPs.insert(trimmed).inserted { added += 1 }
        }
        logger.info("Feodo Tracker: \(added) new C2 IPs")
        return added
    }

    /// URLhaus — malicious URLs and domains.
    /// https://urlhaus.abuse.ch/downloads/text_recent/
    private func updateURLhaus() async -> Int {
        let url = "https://urlhaus.abuse.ch/downloads/text_recent/"
        guard let lines = await fetchLines(url: url) else { return 0 }

        var added = 0
        for line in lines {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.isEmpty || trimmed.hasPrefix("#") { continue }

            // Extract domain from URL
            if let urlObj = URL(string: trimmed), let host = urlObj.host {
                if maliciousDomains.insert(host.lowercased()).inserted { added += 1 }
            }
            if maliciousURLs.insert(trimmed.lowercased()).inserted { added += 1 }
        }
        logger.info("URLhaus: \(added) new malicious URLs/domains")
        return added
    }

    /// MalwareBazaar — recent malware SHA-256 hashes.
    /// https://bazaar.abuse.ch/export/txt/sha256/recent/
    private func updateMalwareBazaar() async -> Int {
        let url = "https://bazaar.abuse.ch/export/txt/sha256/recent/"
        guard let lines = await fetchLines(url: url) else { return 0 }

        var added = 0
        for line in lines {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.isEmpty || trimmed.hasPrefix("#") { continue }
            // Each line is a SHA-256 hash (64 hex chars)
            if trimmed.count == 64, trimmed.allSatisfy({ $0.isHexDigit }) {
                if maliciousHashes.insert(trimmed.lowercased()).inserted { added += 1 }
            }
        }
        logger.info("MalwareBazaar: \(added) new malware hashes")
        return added
    }

    // MARK: - Network

    private nonisolated func fetchLines(url urlString: String) async -> [String]? {
        guard let url = URL(string: urlString) else { return nil }

        do {
            let (data, response) = try await URLSession.shared.data(from: url)
            if let http = response as? HTTPURLResponse, http.statusCode != 200 {
                return nil
            }
            let text = String(data: data, encoding: .utf8) ?? ""
            return text.split(separator: "\n").map(String.init)
        } catch {
            return nil
        }
    }

    // MARK: - Cache Persistence

    private func saveCache() {
        let cache = CacheData(
            hashes: Array(maliciousHashes),
            ips: Array(maliciousIPs),
            domains: Array(maliciousDomains),
            urls: Array(maliciousURLs.prefix(50000)), // Cap URL list
            lastUpdate: lastUpdate
        )
        if let data = try? JSONEncoder().encode(cache) {
            try? data.write(to: URL(fileURLWithPath: cacheDir + "/feed_cache.json"))
        }
    }

    private func loadCachedFeeds() {
        let path = cacheDir + "/feed_cache.json"
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)),
              let cache = try? JSONDecoder().decode(CacheData.self, from: data) else {
            return
        }

        maliciousHashes = Set(cache.hashes)
        maliciousIPs = Set(cache.ips)
        maliciousDomains = Set(cache.domains)
        maliciousURLs = Set(cache.urls)
        lastUpdate = cache.lastUpdate

        logger.info("Loaded cached threat intel: \(self.maliciousHashes.count) hashes, \(self.maliciousIPs.count) IPs, \(self.maliciousDomains.count) domains")
    }

    private func loadCustomIOCFiles() {
        let fm = FileManager.default
        guard let files = try? fm.contentsOfDirectory(atPath: cacheDir) else { return }

        for file in files {
            let path = cacheDir + "/" + file
            if file.hasSuffix(".hashes.txt") {
                try? loadCustomFile(path: path, type: .hash)
            } else if file.hasSuffix(".ips.txt") {
                try? loadCustomFile(path: path, type: .ip)
            } else if file.hasSuffix(".domains.txt") {
                try? loadCustomFile(path: path, type: .domain)
            }
        }
    }

    private struct CacheData: Codable {
        let hashes: [String]
        let ips: [String]
        let domains: [String]
        let urls: [String]
        let lastUpdate: Date?
    }
}
