// ThreatIntelFeed.swift
// MacCrabCore
//
// Downloads and caches indicators of compromise (IOCs) from open threat
// intelligence feeds. Checks processes, files, and network connections
// against known-bad hashes, IPs, and domains.
//
// v1.6.17: every IOC now carries metadata (source feed, first-seen,
// malware family, tags). Feeds switched from the small "_recent" /
// "_recommended" endpoints to the full CSV exports — yields ~50–200×
// more coverage per category and the per-IOC context analysts asked
// for. Per-category caps + age-based eviction keep the cache from
// growing unbounded across 4-hour refresh cycles.

import Foundation
import os.log

/// Manages threat intelligence feeds and IOC lookups.
///
/// Supported feeds:
/// - abuse.ch URLhaus (malicious URLs/domains, full CSV with malware family + tags)
/// - abuse.ch MalwareBazaar (malicious file hashes, full CSV with file_type + signature + tags)
/// - abuse.ch Feodo Tracker (C2 IP addresses, full CSV with first_seen + malware family)
/// - Custom IOC lists (user-provided)
public actor ThreatIntelFeed {

    private let logger = Logger(subsystem: "com.maccrab", category: "threat-intel")

    // MARK: - IOC Records (v1.6.17)
    //
    // Every entry carries metadata so the dashboard can show the
    // analyst what an IOC is, where it came from, and when it was
    // first observed in the wild — answers the "what's a match
    // actually mean?" question that the v1.6.16 browser couldn't.

    public struct IOCRecord: Sendable, Codable, Hashable {
        public let value: String
        public let source: String          // "MalwareBazaar" | "Feodo" | "URLhaus" | "Custom"
        public let firstSeen: Date?        // when the feed first observed it
        public let lastSeenInFeed: Date    // when WE most recently saw it in a refresh — drives age eviction
        public let malwareFamily: String?  // "AsyncRAT", "Cobalt Strike", "Lumma", etc.
        public let tags: [String]          // free-form labels from the feed
        public let fileType: String?       // hashes only — "exe" | "dll" | "macho" | "zip" | …

        public init(value: String, source: String, firstSeen: Date?,
                    lastSeenInFeed: Date = Date(), malwareFamily: String? = nil,
                    tags: [String] = [], fileType: String? = nil) {
            self.value = value
            self.source = source
            self.firstSeen = firstSeen
            self.lastSeenInFeed = lastSeenInFeed
            self.malwareFamily = malwareFamily
            self.tags = tags
            self.fileType = fileType
        }
    }

    // MARK: - IOC Storage (now records, keyed by IOC value)

    private var hashRecords: [String: IOCRecord] = [:]
    private var ipRecords: [String: IOCRecord] = [:]
    private var domainRecords: [String: IOCRecord] = [:]
    private var urlRecords: [String: IOCRecord] = [:]

    /// When feeds were last updated.
    private var lastUpdate: Date?

    /// Per-feed last-success timestamps so the dashboard can show
    /// "URLhaus updated 12 min ago, MalwareBazaar updated 4 h ago".
    private var perFeedLastUpdate: [String: Date] = [:]

    /// Per-feed last error so the dashboard can surface "feed X failed
    /// at HH:MM with reason Y" — turns silent feed-update failures
    /// into a visible signal.
    public struct FeedError: Sendable, Codable {
        public let at: Date
        public let reason: String
    }
    private var perFeedLastError: [String: FeedError] = [:]

    /// Directory for cached feed data.
    private let cacheDir: String

    /// Update interval (default: 4 hours).
    private let updateInterval: TimeInterval

    /// Whether auto-update is running.
    private var isRunning = false

    /// Per-category caps. Bound the cache so a runaway feed (or a
    /// hypothetical malicious mirror) can't drive unbounded heap or
    /// disk growth. Beyond the cap the oldest-by-`lastSeenInFeed`
    /// records are evicted — this preserves the freshest IOCs which
    /// are the ones most likely to match recent attacks.
    public static let defaultMaxHashes = 200_000
    public static let defaultMaxIPs = 25_000
    public static let defaultMaxDomains = 100_000
    public static let defaultMaxURLs = 75_000

    /// Eviction threshold by age. Records that haven't appeared in
    /// any feed refresh for this long are dropped — feeds advertise
    /// IOCs only while they're active, so a stale entry probably
    /// represents a sinkholed / cleaned-up indicator that no longer
    /// reflects live threats.
    public static let defaultMaxAge: TimeInterval = 30 * 86400

    private let maxHashes: Int
    private let maxIPs: Int
    private let maxDomains: Int
    private let maxURLs: Int
    private let maxAge: TimeInterval

    // MARK: - Initialization

    public init(cacheDir: String? = nil,
                updateInterval: TimeInterval = 4 * 3600,
                maxHashes: Int = defaultMaxHashes,
                maxIPs: Int = defaultMaxIPs,
                maxDomains: Int = defaultMaxDomains,
                maxURLs: Int = defaultMaxURLs,
                maxAge: TimeInterval = defaultMaxAge) {
        let dir = cacheDir ?? {
            let appSupport = FileManager.default.urls(
                for: .applicationSupportDirectory,
                in: .userDomainMask
            ).first ?? URL(fileURLWithPath: NSTemporaryDirectory())
            return appSupport.appendingPathComponent("MacCrab/threat_intel").path
        }()
        self.cacheDir = dir
        self.updateInterval = updateInterval
        self.maxHashes = maxHashes
        self.maxIPs = maxIPs
        self.maxDomains = maxDomains
        self.maxURLs = maxURLs
        self.maxAge = maxAge
        try? FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
    }

    // MARK: - Public API

    /// Start auto-updating feeds in the background.
    public func start() {
        isRunning = true

        // Then update from network
        Task {
            // Load cached data first (instant, no network)
            await loadCachedFeeds()

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

    /// Trigger a one-shot feed refresh now. Used by the dashboard's
    /// "Refresh Now" button so analysts don't have to wait the full
    /// 4 h cadence after editing custom IOCs or after a feed outage.
    public func refreshNow() async {
        await updateAllFeeds()
    }

    /// Check if a SHA-256 hash is known-malicious.
    public func isHashMalicious(_ hash: String) -> Bool {
        hashRecords[hash.lowercased()] != nil
    }

    /// Check if an IP address is known-malicious.
    public func isIPMalicious(_ ip: String) -> Bool {
        ipRecords[ip] != nil
    }

    /// Check if a domain is known-malicious.
    public func isDomainMalicious(_ domain: String) -> Bool {
        let lower = domain.lowercased()
        if domainRecords[lower] != nil { return true }
        let parts = lower.split(separator: ".")
        for i in 1..<parts.count {
            let parent = parts[i...].joined(separator: ".")
            if domainRecords[parent] != nil { return true }
        }
        return false
    }

    /// Check a URL against known-malicious URLs.
    public func isURLMalicious(_ url: String) -> Bool {
        let lower = url.lowercased()
        return urlRecords.keys.contains { lower.contains($0) }
    }

    /// Lookup the metadata record for an IOC value (any category).
    /// Returns nil on miss. Used by the alert path to enrich
    /// "this CDHash matched MalwareBazaar — family Lumma, file_type
    /// macho, first seen 2026-04-19" rather than just "matched a
    /// hash."
    public func recordForHash(_ hash: String) -> IOCRecord? { hashRecords[hash.lowercased()] }
    public func recordForIP(_ ip: String) -> IOCRecord? { ipRecords[ip] }
    public func recordForDomain(_ domain: String) -> IOCRecord? { domainRecords[domain.lowercased()] }
    public func recordForURL(_ url: String) -> IOCRecord? {
        let lower = url.lowercased()
        return urlRecords.first(where: { lower.contains($0.key) })?.value
    }

    /// Get statistics about loaded IOCs.
    public func stats() -> (hashes: Int, ips: Int, domains: Int, urls: Int, lastUpdate: Date?) {
        (hashRecords.count, ipRecords.count, domainRecords.count, urlRecords.count, lastUpdate)
    }

    /// Read the on-disk cache file and return its IOC counts without
    /// instantiating a full `ThreatIntelFeed` actor.
    public static func cachedStats(
        at cacheDir: String
    ) -> (hashes: Int, ips: Int, domains: Int, urls: Int, lastUpdate: Date?)? {
        guard let cache = readCache(at: cacheDir) else { return nil }
        return (cache.hashes.count, cache.ips.count, cache.domains.count, cache.urls.count, cache.lastUpdate)
    }

    /// Public read-only view of the IOC cache. Records carry source,
    /// firstSeen, malware family, and tags so the dashboard can render
    /// rich rows instead of bare strings.
    public struct IOCSet: Sendable {
        public let hashes: [IOCRecord]
        public let ips: [IOCRecord]
        public let domains: [IOCRecord]
        public let urls: [IOCRecord]
        public let lastUpdate: Date?
        /// Per-feed health: keyed by feed name, tuple of last success
        /// + last error timestamp + reason. Lets the dashboard say
        /// "URLhaus failed: 503 at HH:MM" instead of just stalling.
        public let perFeedLastUpdate: [String: Date]
        public let perFeedLastError: [String: FeedError]
    }

    /// Read the full IOC set from the daemon-written cache file.
    public static func cachedIOCs(at cacheDir: String) -> IOCSet? {
        guard let cache = readCache(at: cacheDir) else { return nil }
        return IOCSet(
            hashes: cache.hashes,
            ips: cache.ips,
            domains: cache.domains,
            urls: cache.urls,
            lastUpdate: cache.lastUpdate,
            perFeedLastUpdate: cache.perFeedLastUpdate ?? [:],
            perFeedLastError: cache.perFeedLastError ?? [:]
        )
    }

    private static func readCache(at cacheDir: String) -> CacheData? {
        let path = cacheDir + "/feed_cache.json"
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)) else { return nil }
        // v1.6.17 schema. We don't try to read v1.6.16 caches — the
        // feed updater rewrites the cache within hours of upgrade.
        return try? JSONDecoder().decode(CacheData.self, from: data)
    }

    /// Get all known-malicious IPs for bulk blocking.
    public func maliciousIPSet() -> Set<String> {
        Set(ipRecords.keys)
    }

    /// Get all known-malicious domains for DNS sinkholing.
    public func maliciousDomainSet() -> Set<String> {
        Set(domainRecords.keys)
    }

    /// Callback invoked after each feed update with (malicious IPs, malicious domains).
    public typealias FeedUpdateHandler = @Sendable (Set<String>, Set<String>) async -> Void
    private var onFeedUpdate: FeedUpdateHandler?

    public func onUpdate(_ handler: @escaping FeedUpdateHandler) {
        self.onFeedUpdate = handler
    }

    /// Add custom IOCs (user-provided).
    public func addCustomIOCs(hashes: [String] = [], ips: [String] = [], domains: [String] = []) {
        let now = Date()
        for h in hashes {
            let key = h.lowercased()
            hashRecords[key] = IOCRecord(value: key, source: "Custom", firstSeen: now, lastSeenInFeed: now)
        }
        for ip in ips {
            ipRecords[ip] = IOCRecord(value: ip, source: "Custom", firstSeen: now, lastSeenInFeed: now)
        }
        for d in domains {
            let key = d.lowercased()
            domainRecords[key] = IOCRecord(value: key, source: "Custom", firstSeen: now, lastSeenInFeed: now)
        }
    }

    /// Load IOCs from a custom file (one per line, # comments).
    public func loadCustomFile(path: String, type: IOCType) throws {
        let content = try String(contentsOfFile: path, encoding: .utf8)
        let lines = content.split(separator: "\n")
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty && !$0.hasPrefix("#") }

        let now = Date()
        for line in lines {
            let key = line.lowercased()
            let rec = IOCRecord(value: key, source: "Custom", firstSeen: now, lastSeenInFeed: now)
            switch type {
            case .hash:   hashRecords[key] = rec
            case .ip:     ipRecords[line] = rec
            case .domain: domainRecords[key] = rec
            case .url:    urlRecords[key] = rec
            }
        }

        logger.info("Loaded \(lines.count) custom \(type.rawValue) IOCs from \(path)")
    }

    public enum IOCType: String {
        case hash, ip, domain, url
    }

    // MARK: - Feed Updates

    private func updateAllFeeds() async {
        logger.info("Updating threat intelligence feeds…")
        var totalNew = 0

        totalNew += await updateFeodoTracker()
        totalNew += await updateURLhaus()
        totalNew += await updateMalwareBazaar()

        // After every refresh: drop records older than maxAge, then
        // hard-cap each category by lastSeenInFeed (drop the oldest).
        // Order matters: age-purge first because it's the cheaper /
        // more semantically meaningful filter.
        evictStale()
        enforceCaps()

        lastUpdate = Date()
        saveCache()

        let totalCount = hashRecords.count + ipRecords.count + domainRecords.count + urlRecords.count
        logger.info("Threat intel update complete: \(totalNew) new IOCs. Total: \(self.hashRecords.count) hashes, \(self.ipRecords.count) IPs, \(self.domainRecords.count) domains, \(self.urlRecords.count) URLs (\(totalCount) total)")

        if !ipRecords.isEmpty || !domainRecords.isEmpty {
            await onFeedUpdate?(maliciousIPSet(), maliciousDomainSet())
        }
    }

    /// Feodo Tracker — full CSV with first_seen + malware family.
    /// Switched from `ipblocklist_recommended.txt` (~30-300 entries)
    /// to `ipblocklist.csv` (full active C2 set, typically 1k-5k entries).
    /// CSV columns: first_seen,dst_ip,dst_port,c2_status,last_online,malware
    private func updateFeodoTracker() async -> Int {
        let url = "https://feodotracker.abuse.ch/downloads/ipblocklist.csv"
        guard let lines = await fetchLines(url: url, feedName: "Feodo") else { return 0 }

        let now = Date()
        var added = 0
        for line in lines {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.isEmpty || trimmed.hasPrefix("#") { continue }
            let cols = parseCSVLine(trimmed)
            guard cols.count >= 6 else { continue }
            let firstSeen = parseDate(cols[0])
            let ip = cols[1]
            let family = cols[5].isEmpty ? nil : cols[5]
            guard !ip.isEmpty, !ip.contains(",") else { continue }

            let isNew = ipRecords[ip] == nil
            ipRecords[ip] = IOCRecord(
                value: ip, source: "Feodo",
                firstSeen: firstSeen, lastSeenInFeed: now,
                malwareFamily: family
            )
            if isNew { added += 1 }
        }
        perFeedLastUpdate["Feodo"] = now
        perFeedLastError["Feodo"] = nil
        logger.info("Feodo Tracker: \(added) new C2 IPs (total \(self.ipRecords.count))")
        return added
    }

    /// URLhaus — full CSV of online URLs with threat + malware family + tags.
    /// CSV columns: id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
    private func updateURLhaus() async -> Int {
        let url = "https://urlhaus.abuse.ch/downloads/csv_online/"
        guard let lines = await fetchLines(url: url, feedName: "URLhaus") else { return 0 }

        let now = Date()
        var added = 0
        for line in lines {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.isEmpty || trimmed.hasPrefix("#") { continue }
            let cols = parseCSVLine(trimmed)
            guard cols.count >= 7 else { continue }
            let firstSeen = parseDate(cols[1])
            let urlValue = cols[2].lowercased()
            let threat = cols[5].isEmpty ? nil : cols[5]
            let tags = cols[6].split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
            guard !urlValue.isEmpty else { continue }

            let urlRec = IOCRecord(
                value: urlValue, source: "URLhaus",
                firstSeen: firstSeen, lastSeenInFeed: now,
                malwareFamily: threat, tags: tags
            )
            if urlRecords[urlValue] == nil { added += 1 }
            urlRecords[urlValue] = urlRec

            // Derive parent host as a domain entry.
            if let parsed = URL(string: cols[2]), let host = parsed.host?.lowercased(), !host.isEmpty {
                let dRec = IOCRecord(
                    value: host, source: "URLhaus",
                    firstSeen: firstSeen, lastSeenInFeed: now,
                    malwareFamily: threat, tags: tags
                )
                if domainRecords[host] == nil { added += 1 }
                domainRecords[host] = dRec
            }
        }
        perFeedLastUpdate["URLhaus"] = now
        perFeedLastError["URLhaus"] = nil
        logger.info("URLhaus: \(added) new entries (total \(self.urlRecords.count) urls, \(self.domainRecords.count) domains)")
        return added
    }

    /// MalwareBazaar — full CSV of recent samples with file_type + signature + tags.
    /// CSV columns: first_seen_utc,sha256_hash,md5_hash,sha1_hash,reporter,file_name,
    ///              file_type_guess,mime_type,signature,clamav,vtpercent,imphash,…,tags
    private func updateMalwareBazaar() async -> Int {
        let url = "https://bazaar.abuse.ch/export/csv/recent/"
        guard let lines = await fetchLines(url: url, feedName: "MalwareBazaar") else { return 0 }

        let now = Date()
        var added = 0
        for line in lines {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.isEmpty || trimmed.hasPrefix("#") { continue }
            let cols = parseCSVLine(trimmed)
            guard cols.count >= 9 else { continue }
            let firstSeen = parseDate(cols[0])
            let hash = cols[1].lowercased()
            let fileType = cols[6].isEmpty ? nil : cols[6]
            let signature = cols[8].isEmpty ? nil : cols[8]
            // Tags are typically at column index 13+ (varies); do a
            // best-effort grab so we don't depend on column count.
            let tags = cols.count > 13
                ? cols[13].split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
                : []

            guard hash.count == 64, hash.allSatisfy({ $0.isHexDigit }) else { continue }

            let isNew = hashRecords[hash] == nil
            hashRecords[hash] = IOCRecord(
                value: hash, source: "MalwareBazaar",
                firstSeen: firstSeen, lastSeenInFeed: now,
                malwareFamily: signature, tags: tags,
                fileType: fileType
            )
            if isNew { added += 1 }
        }
        perFeedLastUpdate["MalwareBazaar"] = now
        perFeedLastError["MalwareBazaar"] = nil
        logger.info("MalwareBazaar: \(added) new hashes (total \(self.hashRecords.count))")
        return added
    }

    // MARK: - Cap + age eviction

    private func evictStale() {
        let cutoff = Date().addingTimeInterval(-maxAge)
        let beforeH = hashRecords.count
        let beforeI = ipRecords.count
        let beforeD = domainRecords.count
        let beforeU = urlRecords.count
        // Custom-source records are kept regardless — operators want
        // their explicit imports to persist, not be eaten by feed
        // refresh cycles.
        hashRecords = hashRecords.filter { $0.value.source == "Custom" || $0.value.lastSeenInFeed >= cutoff }
        ipRecords = ipRecords.filter { $0.value.source == "Custom" || $0.value.lastSeenInFeed >= cutoff }
        domainRecords = domainRecords.filter { $0.value.source == "Custom" || $0.value.lastSeenInFeed >= cutoff }
        urlRecords = urlRecords.filter { $0.value.source == "Custom" || $0.value.lastSeenInFeed >= cutoff }
        let dropped = (beforeH - hashRecords.count)
            + (beforeI - ipRecords.count)
            + (beforeD - domainRecords.count)
            + (beforeU - urlRecords.count)
        if dropped > 0 {
            logger.info("Evicted \(dropped) stale IOCs older than \(Int(self.maxAge / 86400))d")
        }
    }

    private func enforceCaps() {
        hashRecords = capByLastSeen(hashRecords, max: maxHashes)
        ipRecords = capByLastSeen(ipRecords, max: maxIPs)
        domainRecords = capByLastSeen(domainRecords, max: maxDomains)
        urlRecords = capByLastSeen(urlRecords, max: maxURLs)
    }

    private func capByLastSeen(_ records: [String: IOCRecord], max: Int) -> [String: IOCRecord] {
        guard records.count > max else { return records }
        // Custom records pinned. Among feed records, drop oldest by
        // lastSeenInFeed.
        let custom = records.filter { $0.value.source == "Custom" }
        let feed = records.filter { $0.value.source != "Custom" }
        let keepCount = max - custom.count
        guard keepCount > 0 else { return custom }
        let keptFeed = feed
            .sorted { $0.value.lastSeenInFeed > $1.value.lastSeenInFeed }
            .prefix(keepCount)
        var out = custom
        for (k, v) in keptFeed { out[k] = v }
        return out
    }

    // MARK: - Network

    private nonisolated func fetchLines(url urlString: String, feedName: String? = nil) async -> [String]? {
        guard let url = URL(string: urlString) else { return nil }

        do {
            let (data, response) = try await URLSession.shared.data(from: url)
            if let http = response as? HTTPURLResponse, http.statusCode != 200 {
                if let feedName {
                    await self.recordFeedError(feedName, reason: "HTTP \(http.statusCode)")
                }
                return nil
            }
            let text = String(data: data, encoding: .utf8) ?? ""
            return text.split(separator: "\n").map(String.init)
        } catch {
            if let feedName {
                await self.recordFeedError(feedName, reason: error.localizedDescription)
            }
            return nil
        }
    }

    private func recordFeedError(_ feed: String, reason: String) {
        perFeedLastError[feed] = FeedError(at: Date(), reason: reason)
        logger.warning("Feed update failed: \(feed) — \(reason, privacy: .public)")
    }

    // MARK: - CSV parsing

    /// Minimal CSV line parser handling double-quoted fields with
    /// embedded commas. Suitable for the abuse.ch feed format
    /// (RFC-4180-like with `,` separators and `""` for embedded
    /// quotes). Avoids pulling in a heavyweight CSV dependency.
    private func parseCSVLine(_ line: String) -> [String] {
        var result: [String] = []
        var current = ""
        var inQuotes = false
        var i = line.startIndex
        while i < line.endIndex {
            let c = line[i]
            if inQuotes {
                if c == "\"" {
                    let next = line.index(after: i)
                    if next < line.endIndex && line[next] == "\"" {
                        current.append("\"")
                        i = line.index(after: next)
                        continue
                    } else {
                        inQuotes = false
                    }
                } else {
                    current.append(c)
                }
            } else {
                if c == "," {
                    result.append(current.trimmingCharacters(in: .whitespaces))
                    current = ""
                } else if c == "\"" {
                    inQuotes = true
                } else {
                    current.append(c)
                }
            }
            i = line.index(after: i)
        }
        result.append(current.trimmingCharacters(in: .whitespaces))
        return result
    }

    /// abuse.ch feeds stamp dates as either `YYYY-MM-DD HH:MM:SS` or
    /// `YYYY-MM-DD HH:MM:SS UTC`. Try both, return nil on miss.
    private func parseDate(_ s: String) -> Date? {
        let trimmed = s.trimmingCharacters(in: .whitespaces).replacingOccurrences(of: " UTC", with: "")
        guard !trimmed.isEmpty else { return nil }
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.timeZone = TimeZone(identifier: "UTC")
        f.dateFormat = "yyyy-MM-dd HH:mm:ss"
        if let d = f.date(from: trimmed) { return d }
        f.dateFormat = "yyyy-MM-dd"
        return f.date(from: trimmed)
    }

    // MARK: - Cache Persistence

    private func saveCache() {
        let cache = CacheData(
            hashes: Array(hashRecords.values),
            ips: Array(ipRecords.values),
            domains: Array(domainRecords.values),
            urls: Array(urlRecords.values),
            lastUpdate: lastUpdate,
            perFeedLastUpdate: perFeedLastUpdate,
            perFeedLastError: perFeedLastError
        )
        if let data = try? JSONEncoder().encode(cache) {
            try? data.write(to: URL(fileURLWithPath: cacheDir + "/feed_cache.json"))
            try? FileManager.default.setAttributes(
                [.posixPermissions: 0o644],
                ofItemAtPath: cacheDir + "/feed_cache.json"
            )
        }
    }

    private func loadCachedFeeds() async {
        let path = cacheDir + "/feed_cache.json"
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)),
              let cache = try? JSONDecoder().decode(CacheData.self, from: data) else {
            return
        }

        for r in cache.hashes   { hashRecords[r.value]   = r }
        for r in cache.ips      { ipRecords[r.value]     = r }
        for r in cache.domains  { domainRecords[r.value] = r }
        for r in cache.urls     { urlRecords[r.value]    = r }
        lastUpdate = cache.lastUpdate
        perFeedLastUpdate = cache.perFeedLastUpdate ?? [:]
        perFeedLastError = cache.perFeedLastError ?? [:]

        logger.info("Loaded cached threat intel: \(self.hashRecords.count) hashes, \(self.ipRecords.count) IPs, \(self.domainRecords.count) domains, \(self.urlRecords.count) URLs")

        if !ipRecords.isEmpty || !domainRecords.isEmpty {
            await onFeedUpdate?(maliciousIPSet(), maliciousDomainSet())
        }
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

    fileprivate struct CacheData: Codable {
        let hashes: [IOCRecord]
        let ips: [IOCRecord]
        let domains: [IOCRecord]
        let urls: [IOCRecord]
        let lastUpdate: Date?
        let perFeedLastUpdate: [String: Date]?
        let perFeedLastError: [String: FeedError]?
    }
}
