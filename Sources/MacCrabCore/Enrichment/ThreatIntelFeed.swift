// ThreatIntelFeed.swift
// MacCrabCore
//
// Downloads and caches indicators of compromise (IOCs) from open threat
// intelligence feeds. Checks processes, files, and network connections
// against known-bad hashes, IPs, and domains.
//
// v1.6.17: every IOC now carries metadata (source feed, first-seen,
// malware family, tags). Feeds switched from the small `_recent` /
// `_recommended` per-row endpoints to the CSV exports — yields
// ~10–100× more coverage per category and the per-IOC context
// analysts asked for. Per-category caps + age-based eviction keep
// the cache from growing unbounded across 4-hour refresh cycles.
//
// Endpoint contract (verified 2026-09-07):
// URLhaus and MalwareBazaar use authenticated v2 recent.csv exports.
// Feodo uses its public 30-day CSV IOC list. These are bounded download-only
// datasets, not live queries about this Mac. No malware payload is downloaded.

import Foundation
import os.log

/// Manages threat intelligence feeds and IOC lookups.
///
/// Supported feeds:
/// - abuse.ch URLhaus (malicious URLs/domains; authenticated recent export)
/// - abuse.ch MalwareBazaar (malicious file hashes; authenticated recent export)
/// - abuse.ch Feodo Tracker (C2 IP addresses; `ipblocklist.csv` recent 30 days)
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
        public let source: String          // "MalwareBazaar" | "Feodo" | "URLhaus" | "MISP" | "Custom"
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

    /// When a feed refresh was last *attempted* (success or not).
    private var lastUpdate: Date?

    /// When at least one feed last parsed ≥1 record on a refresh —
    /// i.e. the last time we actually pulled fresh intel rather than
    /// just running the timer. Distinct from `lastUpdate` so the
    /// dashboard can show "last successful pull 12 min ago" even when
    /// the most recent attempt hit empty/200 bodies and was rejected.
    private var lastSuccessfulPull: Date?

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

    /// v1.9 Phase-5.2 (TI-H1): multi-tenant platforms whose bare host
    /// must NOT be inserted as a domain IOC — and whose suffix MUST
    /// NOT trigger a domain-suffix-match in `isDomainMalicious`.
    /// Conservative hard-coded list; full Public Suffix List
    /// integration is a v2.0 task. New entries: add when URLhaus
    /// starts emitting URLs hosted on a new shared platform that
    /// would otherwise produce a blanket FP.
    private static let multiTenantPlatforms: Set<String> = [
        "pages.dev",
        "web.app",
        "firebaseapp.com",
        "vercel.app",
        "netlify.app",
        "github.io",
        "gitlab.io",
        "herokuapp.com",
        "replit.app",
        "repl.co",
        "glitch.me",
        "r2.dev",
        "surge.sh",
        "000webhostapp.com",
        "pythonanywhere.com",
        "cloudfront.net",
        "azurewebsites.net",
        "appspot.com",
    ]

    fileprivate static func isMultiTenantPlatformHost(_ host: String) -> Bool {
        multiTenantPlatforms.contains(host)
    }

    /// Platforms that serve unrelated uploaders from the same hostnames,
    /// told apart only by URL path. A malware URL on one of them says nothing
    /// about the host, so the host never becomes a domain IOC and never
    /// matches as a parent. Unlike `multiTenantPlatforms`, no subdomain here
    /// belongs to a tenant: every `*.githubusercontent.com` host is GitHub's.
    /// Field case: URLhaus URLs on raw.githubusercontent.com and github.com
    /// made `api.github.com` a CRITICAL "known-malicious domain".
    private static let sharedPathTenantDomains: Set<String> = [
        "github.com", "githubusercontent.com", "gitlab.com", "bitbucket.org",
        "google.com", "googleusercontent.com", "doubleclick.net",
        "dropbox.com", "dropboxusercontent.com",
        "discord.com", "discordapp.com", "discordapp.net",
        "live.com", "1drv.ms", "archive.org", "wsimg.com", "cloudinary.com",
        "sendspace.com", "imgbox.com", "mediafire.com", "catbox.moe",
        "pythonhosted.org",
    ]

    static func isSharedPathTenantHost(_ host: String) -> Bool {
        let lower = host.lowercased()
        return sharedPathTenantDomains.contains { lower == $0 || lower.hasSuffix("." + $0) }
    }

    /// Caches written before v1.22.2 hold shared-platform hosts derived from
    /// URLhaus URLs; drop them on read rather than alert until they age out.
    /// Operator (Custom) and MISP entries were imported as domains on purpose.
    static func retainedDomainRecords(_ records: [IOCRecord]) -> [IOCRecord] {
        records.filter { $0.source != "URLhaus" || !isSharedPathTenantHost($0.value) }
    }

    /// Update interval (default: 4 hours).
    private let updateInterval: TimeInterval

    /// Whether auto-update is running.
    private var isRunning = false
    private var networkRefreshTask: Task<Void, Never>?
    private var refreshTask: Task<Void, Never>?
    private var networkGeneration: UInt64 = 0
    private var terminallyStopped = false
    private var shutdownTask: Task<Bool, Never>?

    /// v1.19.1: count of network-fetch attempts (incremented at the top of
    /// updateAllFeeds). Lets tests assert a disabled feed performs ZERO
    /// outbound fetches — the off-by-default privacy invariant. Internal so
    /// `@testable import` can read it.
    private(set) var networkFetchAttempts = 0

    /// Per-category caps. Bound the cache so a runaway feed (or a
    /// hypothetical malicious mirror) can't drive unbounded heap or
    /// disk growth. Beyond the cap the oldest-by-`lastSeenInFeed`
    /// records are evicted — this preserves the freshest IOCs which
    /// are the ones most likely to match recent attacks.
    // v1.6.22: caps cut by 50–66 % across all four IOC types after 2.76 GB
    // resident observation. Each `IOCRecord` averages ~280 B (value + source
    // + dates + family + tags + fileType). The combined cap drop reclaims
    // ~55 MB private heap. Age-based eviction (30-day TTL) plus the new
    // tighter caps keep the feed coverage current without retaining a year
    // of stale IOCs.
    public static let defaultMaxHashes = 100_000   // was 200_000
    public static let defaultMaxIPs = 10_000       // was 25_000
    public static let defaultMaxDomains = 50_000   // was 100_000
    public static let defaultMaxURLs = 25_000      // was 75_000

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
        // v1.12.5 reversal of v1.11.0 RC2 tightening (audit was wrong):
        // 0o700 blocked the user-context dashboard from reading the
        // feed cache. The dashboard's AppState.refreshThreatIntelStats
        // calls `ThreatIntelFeed.cachedIOCs(at:)` directly, which
        // needs traverse (x) on the directory to open the file inside
        // — even though the file itself is 0o644 (world-readable),
        // the dir's 0o700 prevented user-context traversal. Symptom
        // on field machines: Threat Intel panel stuck at feeds=0,
        // iocs=0; Refresh button "ran" but returned nothing because
        // the read path silently failed at the directory level.
        //
        // 0o755 (dir) + 0o644 (file, set in saveCache()) is what
        // /Library/Application Support/MacCrab/integrations_snapshot.json
        // uses, and the original "privacy/timing leak" concern in the
        // v1.11 audit comment is paper-thin for a single-user macOS
        // workstation — anyone reading another user's IOC cache is
        // already inside the machine.
        try? FileManager.default.createDirectory(
            atPath: dir,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: NSNumber(value: Int16(0o755))]
        )
        // `createDirectory(... attributes:)` does NOT chmod an EXISTING
        // directory. On upgrade from v1.11/v1.12 the dir already
        // exists with 0o700 (the broken tightening) — explicitly
        // loosen now.
        try? FileManager.default.setAttributes(
            [.posixPermissions: NSNumber(value: Int16(0o755))],
            ofItemAtPath: dir
        )
    }

    // MARK: - Public API

    /// Start auto-updating feeds in the background.
    @discardableResult
    public func start(networkRefresh: Bool = true) async -> Bool {
        guard !terminallyStopped, !Task.isCancelled else { return false }
        // v1.12.6 Wave 9F: load cache + operator drop-ins BEFORE
        // returning so DaemonSetup's subsequent `BundledThreatIntel.
        // loadInto(...)` + `persistCacheNow()` see the hydrated state.
        // Pre-9F start() kicked off a fire-and-forget Task — the
        // hydration race meant a `persistCacheNow()` called from
        // DaemonSetup could overwrite the on-disk cache with
        // bundled-only IOCs (losing network feed data from prior
        // boots). Awaiting these two steps inline is cheap (single
        // file read + dir scan); the network fetch stays async.
        //
        // v1.19.1: this LOCAL hydration always runs — it makes NO network
        // request — so detection has bundled + cached + operator-drop-in IOCs
        // even when network refresh is off. Only the periodic abuse.ch fetch
        // (`updateAllFeeds`) is gated by the opt-in `networkRefresh` flag.
        await loadCachedFeeds()
        guard !terminallyStopped, !Task.isCancelled else { return false }

        // v1.9 Phase-5.7 (TI-M7): wire the operator's drop-in
        // *.hashes.txt / *.ips.txt / *.domains.txt files at boot.
        // Pre-fix loadCustomIOCFiles() existed but was never
        // called, so any operator who placed files in the cache
        // dir got no behaviour. Custom IOCs are pinned through
        // the age-eviction (source == "Custom" survives).
        loadCustomIOCFiles()

        if networkRefresh {
            return startNetworkRefresh()
        }
        return true
    }

    /// Launch the periodic abuse.ch network-refresh loop (immediate fetch, then
    /// every `updateInterval`). Idempotent: a call while already running is a
    /// no-op. The actual OUTBOUND request lives only in `updateAllFeeds()`.
    @discardableResult
    private func startNetworkRefresh() -> Bool {
        guard !terminallyStopped else { return false }
        if isRunning { return true }
        guard networkRefreshTask == nil, refreshTask == nil else {
            logger.error("Threat-intel refresh cannot restart until prior owned work has drained")
            return false
        }
        isRunning = true
        networkGeneration &+= 1
        let generation = networkGeneration
        networkRefreshTask = Task { [weak self] in
            await self?.runNetworkRefreshLoop(generation: generation)
            await self?.finishNetworkRefreshLoop(generation: generation)
        }
        return true
    }

    private func runNetworkRefreshLoop(generation: UInt64) async {
        await refreshOnce(generation: generation)
        while networkMutationAllowed(generation: generation) {
            do {
                try await Task.sleep(
                    nanoseconds: UInt64(updateInterval * 1_000_000_000)
                )
            } catch {
                break
            }
            guard networkMutationAllowed(generation: generation) else {
                break
            }
            await refreshOnce(generation: generation)
        }
    }

    private func finishNetworkRefreshLoop(generation: UInt64) {
        guard !terminallyStopped,
              generation == networkGeneration else { return }
        networkRefreshTask = nil
    }

    /// Coalesce periodic, SIGHUP, inbox, and dashboard refreshes behind one
    /// retained request. This avoids concurrent full-feed downloads and gives
    /// pause/shutdown an exact task handle to cancel and join.
    private func refreshOnce(generation: UInt64) async {
        guard networkMutationAllowed(generation: generation) else { return }
        if let refreshTask {
            await refreshTask.value
            return
        }
        let task = Task { [weak self] in
            await self?.updateAllFeeds(generation: generation)
            await self?.finishRefresh(generation: generation)
        }
        refreshTask = task
        await task.value
    }

    private func finishRefresh(generation: UInt64) {
        guard !terminallyStopped,
              generation == networkGeneration else { return }
        refreshTask = nil
    }

    private func networkMutationAllowed(generation: UInt64) -> Bool {
        !terminallyStopped
            && isRunning
            && generation == networkGeneration
            && !Task.isCancelled
    }

    /// v1.19.1: live toggle for the opt-in network refresh. Enabling starts the
    /// loop (with an immediate fetch); disabling halts it so egress stops
    /// without a daemon restart. Wired from the SIGHUP config-reload handler.
    @discardableResult
    public func setNetworkRefresh(_ enabled: Bool) async -> Bool {
        if enabled {
            return startNetworkRefresh()
        } else {
            return await pauseNetworkRefresh()
        }
    }

    private func pauseNetworkRefresh(
        deadline: TimeInterval = 1.0
    ) async -> Bool {
        isRunning = false
        let periodic = networkRefreshTask
        let refresh = refreshTask
        periodic?.cancel()
        refresh?.cancel()
        let accepted = [periodic, refresh].compactMap { $0 }
        let joined = await CollectorBoundedTaskJoin.waitForAll(
            accepted,
            deadline: deadline
        )
        if joined {
            networkRefreshTask = nil
            refreshTask = nil
        }
        return joined
    }

    /// v1.12.6 Wave 9F: persist the current in-memory IOC set to
    /// disk RIGHT NOW. Used by DaemonSetup after
    /// `BundledThreatIntel.loadInto(...)` so the dashboard's first
    /// Intelligence-tab mount sees bundled IOCs even before the
    /// initial network fetch (~14 min latency on first cold boot
    /// across all three abuse.ch feeds) has finished. Safe to call
    /// after `start()` because start now awaits `loadCachedFeeds()`
    /// inline — so the in-memory state on warm boot already
    /// contains the previous cache file's network IOCs before we
    /// rewrite the file.
    public func persistCacheNow() {
        guard !terminallyStopped else { return }
        saveCache()
    }

    /// Terminally stop auto-updating. Unlike the live config toggle, this seals
    /// the actor against later refresh resurrection by a delayed startup/SIGHUP
    /// task and joins the exact periodic + in-flight request prefix.
    @discardableResult
    public func stop(deadline: TimeInterval = 1.0) async -> Bool {
        if let shutdownTask { return await shutdownTask.value }
        if terminallyStopped { return true }
        terminallyStopped = true
        isRunning = false
        onFeedUpdate = nil
        let periodic = networkRefreshTask
        let refresh = refreshTask
        periodic?.cancel()
        refresh?.cancel()
        let accepted = [periodic, refresh].compactMap { $0 }
        let waiter = Task {
            await CollectorBoundedTaskJoin.waitForAll(
                accepted,
                deadline: deadline
            )
        }
        shutdownTask = waiter
        let joined = await waiter.value
        if joined {
            networkRefreshTask = nil
            refreshTask = nil
        }
        return joined
    }

    /// Trigger a one-shot feed refresh now. Used by the dashboard's
    /// "Refresh Now" button so analysts don't have to wait the full
    /// 4 h cadence after editing custom IOCs or after a feed outage.
    public func refreshNow() async {
        // v1.19.1: a no-op when the opt-in network refresh isn't running
        // (threat-intel disabled → isRunning false). This gates EVERY caller —
        // the SIGHUP handler, the refresh-intel inbox request, and the
        // dashboard's "Refresh Now" button — so none of them can egress to
        // abuse.ch while threat-intel enrichment is off.
        guard isRunning, !terminallyStopped else { return }
        await refreshOnce(generation: networkGeneration)
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
    /// v1.9 Phase-5.2 (TI-H1): the suffix walk that follows the
    /// exact-match check skips known multi-tenant platform suffixes
    /// (`pages.dev`, `vercel.app`, etc.) so a single bad
    /// `attacker.pages.dev` IOC doesn't blanket-flag every legitimate
    /// site under the same platform.
    public func isDomainMalicious(_ domain: String) -> Bool {
        let lower = domain.lowercased()
        if domainRecords[lower] != nil { return true }
        let parts = lower.split(separator: ".")
        for i in 1..<parts.count {
            let parent = parts[i...].joined(separator: ".")
            if Self.isMultiTenantPlatformHost(parent) || Self.isSharedPathTenantHost(parent) { continue }
            if domainRecords[parent] != nil { return true }
        }
        return false
    }

    /// Check a URL against known-malicious URLs.
    /// v1.9 Phase-5.3 (TI-H2): anchored match. Pre-fix used
    /// `lower.contains($0)` which would FP on innocuous URLs that
    /// share a substring with any short feed entry. The IOC URL must
    /// either equal the queried URL exactly OR be a true prefix.
    public func isURLMalicious(_ url: String) -> Bool {
        let lower = url.lowercased()
        if urlRecords[lower] != nil { return true }
        return urlRecords.keys.contains { ioc in
            lower.hasPrefix(ioc)
        }
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
        // v1.9 Phase-5.3 (TI-H2): anchored — exact match first, then
        // prefix. Mirrors isURLMalicious's anchored semantics.
        if let direct = urlRecords[lower] { return direct }
        return urlRecords.first(where: { lower.hasPrefix($0.key) })?.value
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
        /// Last time ANY feed actually parsed ≥1 record. Lets the
        /// dashboard show a truthful "last successful pull" even when
        /// the most recent attempt was an empty/200 body that we
        /// rejected (so `lastUpdate` advanced but no intel changed).
        public let lastSuccessfulPull: Date?
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
            domains: retainedDomainRecords(cache.domains),
            urls: cache.urls,
            lastUpdate: cache.lastUpdate,
            lastSuccessfulPull: cache.lastSuccessfulPull,
            perFeedLastUpdate: cache.perFeedLastUpdate ?? [:],
            perFeedLastError: cache.perFeedLastError ?? [:]
        )
    }

    /// v1.9 Phase-5.6 (TI-M5): which feeds haven't refreshed in
    /// `staleMultiplier × updateInterval` (default 2×). Returns
    /// (feedName, lastSuccess) pairs. Empty when everything is
    /// fresh OR when no feeds have run yet (cold start).
    public func staleFeeds(staleMultiplier: Double = 2.0) -> [(String, Date)] {
        let threshold = Date().addingTimeInterval(-(updateInterval * staleMultiplier))
        let knownFeeds = ["URLhaus", "MalwareBazaar", "Feodo"]
        var stale: [(String, Date)] = []
        for feed in knownFeeds {
            guard let last = perFeedLastUpdate[feed] else { continue }
            if last < threshold {
                stale.append((feed, last))
            }
        }
        return stale
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
        guard !terminallyStopped else { return }
        self.onFeedUpdate = handler
    }

    /// Result of an import call. The dashboard renders these counts so
    /// users see "imported 47, rejected 3 malformed entries: foo, bar,
    /// TODO" instead of silently polluting the IOC list with garbage.
    public struct ImportResult: Sendable {
        public let accepted: Int
        public let rejected: [String]   // first N malformed values, capped
    }

    /// Maximum number of rejected lines reported back to the caller —
    /// enough to spot the pattern, bounded so a 100K-line garbage file
    /// doesn't blow up the result struct.
    public static let importRejectionReportCap = 25

    /// Add custom IOCs (user-provided). Each input is validated before
    /// insertion: garbage strings are rejected and reported back rather
    /// than polluting the IOC store. Pre-v1.6.18 this method accepted
    /// any string regardless of shape — a user pasting "hello world"
    /// got it inserted as a domain.
    @discardableResult
    public func addCustomIOCs(
        hashes: [String] = [],
        ips: [String] = [],
        domains: [String] = []
    ) -> ImportResult {
        importIOCs(hashes: hashes, ips: ips, domains: domains, source: "Custom")
    }

    /// Recurring MISP results are feed observations, not operator-pinned IOCs.
    /// Apply retention here even when the independent abuse.ch refresh is off.
    /// A failed/empty import leaves the last good cache intact. Accepted counts
    /// describe validated observations; the shared category caps may evict older
    /// feed records from that set before this call returns.
    ///
    /// Older releases persisted MISP observations as `Custom`. Those records
    /// cannot be distinguished from genuine operator input and remain pinned.
    @discardableResult
    public func addMISPIOCs(
        hashes: [String] = [],
        ips: [String] = [],
        domains: [String] = []
    ) -> ImportResult {
        let result = importIOCs(hashes: hashes, ips: ips, domains: domains, source: "MISP")
        if result.accepted > 0 {
            evictStale()
            enforceCaps()
        }
        return result
    }

    /// A feed refresh must never erase an operator's independent reason to
    /// retain the same value. Otherwise the latest actual feed observation
    /// supplies provenance and freshness; do not attribute a MISP observation
    /// to an older record's different feed.
    static func mergingFeedRecord(_ incoming: IOCRecord, existing: IOCRecord?) -> IOCRecord {
        if let existing, existing.source == "Custom" {
            return existing
        }
        return incoming
    }

    private func importIOCs(
        hashes: [String], ips: [String], domains: [String], source: String
    ) -> ImportResult {
        guard !terminallyStopped else {
            var rejected: [String] = []
            for category in [hashes, ips, domains] {
                for candidate in category
                    where rejected.count < Self.importRejectionReportCap {
                    rejected.append(candidate)
                }
                if rejected.count >= Self.importRejectionReportCap { break }
            }
            return ImportResult(accepted: 0, rejected: rejected)
        }
        let now = Date()
        // MISP's categorized import does not carry the provider's first-seen
        // timestamp. Only our last observation is known for those records.
        let firstSeen: Date? = source == "Custom" ? now : nil
        var accepted = 0
        var rejected: [String] = []

        for h in hashes {
            let trimmed = h.trimmingCharacters(in: .whitespaces)
            guard let normalized = Self.validateHash(trimmed) else {
                if rejected.count < Self.importRejectionReportCap { rejected.append(trimmed) }
                continue
            }
            let record = IOCRecord(value: normalized, source: source, firstSeen: firstSeen, lastSeenInFeed: now)
            hashRecords[normalized] = source == "Custom" ? record
                : Self.mergingFeedRecord(record, existing: hashRecords[normalized])
            accepted += 1
        }
        for ip in ips {
            let trimmed = ip.trimmingCharacters(in: .whitespaces)
            guard let normalized = Self.validateIP(trimmed) else {
                if rejected.count < Self.importRejectionReportCap { rejected.append(trimmed) }
                continue
            }
            let record = IOCRecord(value: normalized, source: source, firstSeen: firstSeen, lastSeenInFeed: now)
            ipRecords[normalized] = source == "Custom" ? record
                : Self.mergingFeedRecord(record, existing: ipRecords[normalized])
            accepted += 1
        }
        for d in domains {
            let trimmed = d.trimmingCharacters(in: .whitespaces)
            guard let normalized = Self.validateDomain(trimmed) else {
                if rejected.count < Self.importRejectionReportCap { rejected.append(trimmed) }
                continue
            }
            let record = IOCRecord(value: normalized, source: source, firstSeen: firstSeen, lastSeenInFeed: now)
            domainRecords[normalized] = source == "Custom" ? record
                : Self.mergingFeedRecord(record, existing: domainRecords[normalized])
            accepted += 1
        }
        if !rejected.isEmpty {
            logger.warning("\(source, privacy: .public) IOC import: rejected \(rejected.count) malformed entries (accepted \(accepted))")
        }
        return ImportResult(accepted: accepted, rejected: rejected)
    }

    /// Load IOCs from a custom file (one per line, # comments).
    /// Validates per the file's declared `type`. Returns counts so the
    /// caller can surface "loaded N, rejected K" rather than silently
    /// dropping malformed lines.
    @discardableResult
    public func loadCustomFile(path: String, type: IOCType) throws -> ImportResult {
        guard !terminallyStopped else {
            return ImportResult(accepted: 0, rejected: [path])
        }
        let content = try String(contentsOfFile: path, encoding: .utf8)
        let lines = content.split(separator: "\n")
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty && !$0.hasPrefix("#") }

        let now = Date()
        var accepted = 0
        var rejected: [String] = []
        for line in lines {
            let normalized: String?
            switch type {
            case .hash:   normalized = Self.validateHash(line)
            case .ip:     normalized = Self.validateIP(line)
            case .domain: normalized = Self.validateDomain(line)
            case .url:    normalized = Self.validateURL(line)
            }
            guard let normalized else {
                if rejected.count < Self.importRejectionReportCap { rejected.append(line) }
                continue
            }
            let rec = IOCRecord(value: normalized, source: "Custom", firstSeen: now, lastSeenInFeed: now)
            switch type {
            case .hash:   hashRecords[normalized] = rec
            case .ip:     ipRecords[normalized] = rec
            case .domain: domainRecords[normalized] = rec
            case .url:    urlRecords[normalized] = rec
            }
            accepted += 1
        }

        logger.info("Loaded \(accepted) custom \(type.rawValue) IOCs from \(path)\(rejected.isEmpty ? "" : " (rejected \(rejected.count) malformed)")")
        return ImportResult(accepted: accepted, rejected: rejected)
    }

    public enum IOCType: String {
        case hash, ip, domain, url
    }

    // MARK: - IOC validators
    //
    // Conservative shape checks. Goal is to catch obvious garbage
    // (placeholder text, partial pastes, unparseable strings), not to
    // perfectly canonicalize every edge case. False rejections from
    // these are recoverable — the user sees the rejection in the UI
    // and can fix the input — whereas false acceptances pollute the
    // IOC list silently.

    /// SHA-256 (preferred), SHA-1, or MD5. Returns the lowercased,
    /// trimmed hex string; nil for anything that isn't pure hex of
    /// one of those lengths.
    public static func validateHash(_ s: String) -> String? {
        let h = s.trimmingCharacters(in: .whitespaces).lowercased()
        guard h.count == 64 || h.count == 40 || h.count == 32 else { return nil }
        return h.allSatisfy({ $0.isHexDigit }) ? h : nil
    }

    /// Numeric IPv4 (`a.b.c.d`, each 0-255) or IPv6 (any colon-bearing
    /// form `getaddrinfo` accepts). Returns the input string on
    /// success, nil otherwise. Hostnames are NOT accepted — those
    /// belong in the domains category.
    public static func validateIP(_ s: String) -> String? {
        let v = s.trimmingCharacters(in: .whitespaces)
        guard !v.isEmpty else { return nil }
        // IPv4: 4 dot-separated octets in [0..255]
        let parts = v.split(separator: ".")
        if parts.count == 4, parts.allSatisfy({
            if let n = Int($0), n >= 0, n <= 255, String(n) == String($0) { return true }
            return false
        }) {
            return v
        }
        // IPv6: must contain at least one colon and be parseable by
        // getaddrinfo with AI_NUMERICHOST so we never accept a name.
        if v.contains(":") {
            var hints = addrinfo()
            hints.ai_family = AF_UNSPEC
            hints.ai_flags = AI_NUMERICHOST
            var result: UnsafeMutablePointer<addrinfo>? = nil
            if getaddrinfo(v, nil, &hints, &result) == 0 {
                if let r = result { freeaddrinfo(r) }
                return v
            }
        }
        return nil
    }

    /// Domain shape: at least one dot, only domain-legal characters,
    /// each label 1-63 chars, total <=253. Lowercased.
    public static func validateDomain(_ s: String) -> String? {
        let d = s.trimmingCharacters(in: .whitespaces).lowercased()
        guard !d.isEmpty, d.count <= 253 else { return nil }
        // Reject if it looks like a URL or has a path/query — that's a
        // URL, not a domain, and silently stripping confuses operators.
        if d.contains("://") || d.contains("/") || d.contains("?")
           || d.contains("#") || d.contains(" ") {
            return nil
        }
        let labels = d.split(separator: ".", omittingEmptySubsequences: false)
        guard labels.count >= 2, labels.allSatisfy({
            !$0.isEmpty && $0.count <= 63 && $0.allSatisfy({ ch in
                ch.isLetter || ch.isNumber || ch == "-" || ch == "_"
            }) && !$0.hasPrefix("-") && !$0.hasSuffix("-")
        }) else { return nil }
        // Reject domains where the rightmost label (TLD) is purely
        // numeric — likely a bare IPv4 the user mis-categorized.
        if let last = labels.last, last.allSatisfy({ $0.isNumber }) {
            return nil
        }
        return d
    }

    /// URL must be parseable by Foundation `URL` AND have a scheme of
    /// http/https/ftp (the schemes URLhaus carries) AND have a host.
    public static func validateURL(_ s: String) -> String? {
        let u = s.trimmingCharacters(in: .whitespaces)
        guard let url = URL(string: u),
              let scheme = url.scheme?.lowercased(),
              ["http", "https", "ftp"].contains(scheme),
              let host = url.host, !host.isEmpty else { return nil }
        return u.lowercased()
    }

    // MARK: - Feed Updates

    private func updateAllFeeds(generation: UInt64) async {
        guard networkMutationAllowed(generation: generation) else { return }
        networkFetchAttempts += 1   // v1.19.1: every outbound-fetch attempt (privacy invariant test seam)
        logger.info("Updating threat intelligence feeds…")
        var totalNew = 0
        var anySuccess = false

        let feodo = await updateFeodoTracker(generation: generation)
        guard networkMutationAllowed(generation: generation) else { return }
        let urlhaus = await updateURLhaus(generation: generation)
        guard networkMutationAllowed(generation: generation) else { return }
        let bazaar = await updateMalwareBazaar(generation: generation)
        guard networkMutationAllowed(generation: generation) else { return }
        totalNew += feodo.added + urlhaus.added + bazaar.added
        anySuccess = feodo.success || urlhaus.success || bazaar.success

        // After every refresh: drop records older than maxAge, then
        // hard-cap each category by lastSeenInFeed (drop the oldest).
        // Order matters: age-purge first because it's the cheaper /
        // more semantically meaningful filter.
        evictStale()
        enforceCaps()

        lastUpdate = Date()
        // Only advance the "last successful pull" marker when at least
        // one feed actually parsed records. A cycle where every feed
        // returned an empty/200 body keeps the prior good marker so the
        // operator sees the real freshness, not a freshly-stamped lie.
        if anySuccess { lastSuccessfulPull = Date() }
        saveCache()

        let totalCount = hashRecords.count + ipRecords.count + domainRecords.count + urlRecords.count
        logger.info("Threat intel update complete: \(totalNew) new IOCs. Total: \(self.hashRecords.count) hashes, \(self.ipRecords.count) IPs, \(self.domainRecords.count) domains, \(self.urlRecords.count) URLs (\(totalCount) total)")

        if !ipRecords.isEmpty || !domainRecords.isEmpty {
            await onFeedUpdate?(maliciousIPSet(), maliciousDomainSet())
        }
    }

    /// Feodo Tracker — full CSV with first_seen + malware family.
    /// Switched from `ipblocklist_recommended.txt` (~30-300 entries)
    /// to `ipblocklist.csv` (C2s observed in the recent 30-day window).
    /// CSV columns: first_seen,dst_ip,dst_port,c2_status,last_online,malware
    private func updateFeodoTracker(
        generation: UInt64
    ) async -> (added: Int, success: Bool) {
        // fetchLines records its own error (HTTP non-2xx / exception)
        // and returns nil — leave the prior good cache + marker intact.
        guard let lines = await fetchLines(
            feed: .feodo,
            generation: generation
        ), networkMutationAllowed(generation: generation) else {
            return (0, false)
        }

        let now = Date()
        var added = 0
        var parsed = 0
        for line in lines {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.isEmpty || trimmed.hasPrefix("#") { continue }
            let cols = parseCSVLine(trimmed)
            guard cols.count >= 6 else { continue }
            let firstSeen = parseDate(cols[0])
            let ip = cols[1]
            let family = cols[5].isEmpty ? nil : cols[5]
            guard !ip.isEmpty, !ip.contains(",") else { continue }

            parsed += 1
            let isNew = ipRecords[ip] == nil
            let record = IOCRecord(
                value: ip, source: "Feodo",
                firstSeen: firstSeen, lastSeenInFeed: now,
                malwareFamily: family
            )
            ipRecords[ip] = Self.mergingFeedRecord(record, existing: ipRecords[ip])
            if isNew { added += 1 }
        }
        // A 200 with an empty / unparseable body parses ZERO records.
        // Treat that as a failure: do NOT stamp the success marker (so
        // we don't freeze the count at the bundled set and report a
        // fake "just updated") and surface the reason on the dashboard.
        guard parsed > 0 else {
            recordFeedError(
                "Feodo",
                reason: "0 records parsed (empty feed)",
                generation: generation
            )
            return (0, false)
        }
        perFeedLastUpdate["Feodo"] = now
        perFeedLastError["Feodo"] = nil
        logger.info("Feodo Tracker: \(added) new C2 IPs (total \(self.ipRecords.count))")
        return (added, true)
    }

    /// URLhaus — authenticated recent CSV with threat + malware family + tags.
    /// CSV columns: id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
    private func updateURLhaus(
        generation: UInt64
    ) async -> (added: Int, success: Bool) {
        guard let lines = await fetchLines(
            feed: .urlhaus,
            generation: generation
        ), networkMutationAllowed(generation: generation) else {
            return (0, false)
        }

        let now = Date()
        var added = 0
        var parsed = 0
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

            parsed += 1
            let urlRec = IOCRecord(
                value: urlValue, source: "URLhaus",
                firstSeen: firstSeen, lastSeenInFeed: now,
                malwareFamily: threat, tags: tags
            )
            if urlRecords[urlValue] == nil { added += 1 }
            urlRecords[urlValue] = Self.mergingFeedRecord(urlRec, existing: urlRecords[urlValue])

            // Derive parent host as a domain entry.
            // v1.9 Phase-5.2 (TI-H1): refuse to insert when the host
            // IS itself a multi-tenant platform (e.g. URLhaus
            // emitting a takedown URL whose host is bare `pages.dev`).
            // The exact-match check still fires on full subdomains
            // like `attacker.pages.dev`; the suffix walk in
            // `isDomainMalicious` is bounded against the same
            // platform set so a hostile feed entry can't blanket-flag
            // siblings.
            if let parsed = URL(string: cols[2]), let host = parsed.host?.lowercased(), !host.isEmpty {
                if Self.isMultiTenantPlatformHost(host) || Self.isSharedPathTenantHost(host) {
                    logger.info("URLhaus: skipped platform-suffix host \(host, privacy: .public)")
                    continue
                }
                let dRec = IOCRecord(
                    value: host, source: "URLhaus",
                    firstSeen: firstSeen, lastSeenInFeed: now,
                    malwareFamily: threat, tags: tags
                )
                if domainRecords[host] == nil { added += 1 }
                domainRecords[host] = Self.mergingFeedRecord(dRec, existing: domainRecords[host])
            }
        }
        guard parsed > 0 else {
            recordFeedError(
                "URLhaus",
                reason: "0 records parsed (empty feed)",
                generation: generation
            )
            return (0, false)
        }
        perFeedLastUpdate["URLhaus"] = now
        perFeedLastError["URLhaus"] = nil
        logger.info("URLhaus: \(added) new entries (total \(self.urlRecords.count) urls, \(self.domainRecords.count) domains)")
        return (added, true)
    }

    /// MalwareBazaar — full CSV of recent samples with file_type + signature + tags.
    /// CSV columns: first_seen_utc,sha256_hash,md5_hash,sha1_hash,reporter,file_name,
    ///              file_type_guess,mime_type,signature,clamav,vtpercent,imphash,…,tags
    private func updateMalwareBazaar(
        generation: UInt64
    ) async -> (added: Int, success: Bool) {
        guard let lines = await fetchLines(
            feed: .malwareBazaar,
            generation: generation
        ), networkMutationAllowed(generation: generation) else {
            return (0, false)
        }

        let now = Date()
        var added = 0
        var parsed = 0
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

            parsed += 1
            let isNew = hashRecords[hash] == nil
            let record = IOCRecord(
                value: hash, source: "MalwareBazaar",
                firstSeen: firstSeen, lastSeenInFeed: now,
                malwareFamily: signature, tags: tags,
                fileType: fileType
            )
            hashRecords[hash] = Self.mergingFeedRecord(record, existing: hashRecords[hash])
            if isNew { added += 1 }
        }
        guard parsed > 0 else {
            recordFeedError(
                "MalwareBazaar",
                reason: "0 records parsed (empty feed)",
                generation: generation
            )
            return (0, false)
        }
        perFeedLastUpdate["MalwareBazaar"] = now
        perFeedLastError["MalwareBazaar"] = nil
        logger.info("MalwareBazaar: \(added) new hashes (total \(self.hashRecords.count))")
        return (added, true)
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

    private nonisolated func fetchLines(
        feed: ThreatIntelDownloadContract.Feed,
        generation: UInt64
    ) async -> [String]? {
        do {
            let authKey: String?
            if feed == .feodo {
                authKey = nil
            } else {
                do {
                    // Shared Keychain is authoritative. Keep the existing
                    // environment fallback for manually launched installations
                    // only when no persistent item exists, never on read error.
                    authKey = try SecretsStore().getNonInteractive(.abuseCHAuthKey)
                        ?? Foundation.ProcessInfo.processInfo.environment["MACCRAB_ABUSECH_AUTH_KEY"]
                } catch { throw ThreatIntelDownloadContract.Failure.credentialUnavailable }
            }
            let request = try ThreatIntelDownloadContract.request(feed: feed, authKey: authKey)
            let (bytes, response) = try await ThreatIntelDownloadSession.shared.bytes(for: request)
            guard let http = response as? HTTPURLResponse, http.statusCode == 200 else {
                bytes.task.cancel()
                let status = (response as? HTTPURLResponse)?.statusCode ?? 0
                await self.recordFeedError(feed.rawValue, reason: "HTTP \(status); cached indicators are retained.", generation: generation)
                return nil
            }
            guard response.expectedContentLength <= ThreatIntelDownloadContract.maximumResponseBytes else {
                bytes.task.cancel()
                throw ThreatIntelDownloadContract.Failure.oversizedResponse
            }
            var data = Data()
            do {
                for try await byte in bytes {
                    guard data.count < ThreatIntelDownloadContract.maximumResponseBytes else {
                        throw ThreatIntelDownloadContract.Failure.oversizedResponse
                    }
                    data.append(byte)
                }
            } catch {
                bytes.task.cancel()
                throw error
            }
            guard let text = String(data: data, encoding: .utf8) else {
                await self.recordFeedError(feed.rawValue, reason: "Feed is not UTF-8; cached indicators are retained.", generation: generation)
                return nil
            }
            return Self.splitFeedLines(text)
        } catch {
            await self.recordFeedError(feed.rawValue,
                reason: ThreatIntelDownloadContract.sanitizedFailure(error), generation: generation)
            return nil
        }
    }

    /// Split a feed body into lines on ANY Unicode newline.
    ///
    /// The abuse.ch feeds (URLhaus, MalwareBazaar, Feodo) ship CRLF
    /// line endings. Swift treats "\r\n" as a SINGLE extended grapheme
    /// cluster, so `split(separator: "\n")` finds no standalone "\n"
    /// Character and returns the entire body as ONE line — which begins
    /// with a "#" comment and parses to ZERO records, silently breaking
    /// every CRLF feed. Splitting on `isNewline` handles CRLF / LF / CR
    /// (and U+2028/U+2029) uniformly and consumes the "\r\n" pair as a
    /// single separator, so callers never see a trailing "\r".
    static func splitFeedLines(_ text: String) -> [String] {
        text.split(whereSeparator: { $0.isNewline }).map(String.init)
    }

    private func recordFeedError(
        _ feed: String,
        reason: String,
        generation: UInt64
    ) {
        guard networkMutationAllowed(generation: generation) else { return }
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
            lastSuccessfulPull: lastSuccessfulPull,
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
        for r in Self.retainedDomainRecords(cache.domains) { domainRecords[r.value] = r }
        for r in cache.urls     { urlRecords[r.value]    = r }
        lastUpdate = cache.lastUpdate
        lastSuccessfulPull = cache.lastSuccessfulPull
        perFeedLastUpdate = cache.perFeedLastUpdate ?? [:]
        perFeedLastError = cache.perFeedLastError ?? [:]

        logger.info("Loaded cached threat intel: \(self.hashRecords.count) hashes, \(self.ipRecords.count) IPs, \(self.domainRecords.count) domains, \(self.urlRecords.count) URLs")

        if !ipRecords.isEmpty || !domainRecords.isEmpty {
            await onFeedUpdate?(maliciousIPSet(), maliciousDomainSet())
        }
    }

    /// Ingest operator-supplied custom IOC drop files from the threat-intel
    /// cache dir. Each file is validated before reading: must NOT be a
    /// symlink (so an attacker who plants a symlink can't redirect us to
    /// /etc/passwd or similar), must be owned by the same uid as the
    /// daemon process (so a non-root attacker can't poison the production
    /// IOC store), and must live directly inside `cacheDir` (no path
    /// traversal via `..`). On any validation failure we log + skip the
    /// file rather than fail-open by ingesting it.
    private func loadCustomIOCFiles() {
        let fm = FileManager.default
        guard let files = try? fm.contentsOfDirectory(atPath: cacheDir) else { return }
        let myUID = getuid()

        for file in files {
            let path = cacheDir + "/" + file

            let suffixOK = file.hasSuffix(".hashes.txt")
                || file.hasSuffix(".ips.txt")
                || file.hasSuffix(".domains.txt")
                || file.hasSuffix(".urls.txt")   // v1.21.4 (audit): custom URL IOCs
            guard suffixOK else { continue }

            // Reject path traversal — file name must be a leaf inside cacheDir.
            guard !file.contains("/") && !file.contains("..") else {
                logger.warning("custom IOC: rejecting suspicious filename \(file, privacy: .public)")
                continue
            }

            // lstat (not stat) so we see the symlink itself, not its target.
            guard let attrs = try? fm.attributesOfItem(atPath: path) else {
                logger.warning("custom IOC: cannot stat \(path, privacy: .public)")
                continue
            }
            if (attrs[.type] as? FileAttributeType) == .typeSymbolicLink {
                logger.error("custom IOC: refusing to follow symlink \(path, privacy: .public)")
                continue
            }
            if (attrs[.type] as? FileAttributeType) != .typeRegular {
                logger.warning("custom IOC: \(path, privacy: .public) is not a regular file — skipping")
                continue
            }
            // File ownership must match the daemon's uid OR be root-owned
            // (sysext runs as root, dev daemon runs as the user). A file
            // owned by *another* user means somebody else dropped it
            // there, which we don't trust.
            let fileUID = (attrs[.ownerAccountID] as? UInt32) ?? UInt32.max
            if fileUID != myUID && fileUID != 0 {
                logger.error("custom IOC: \(path, privacy: .public) owned by uid \(fileUID, privacy: .public), expected \(myUID, privacy: .public) or 0 — refusing")
                continue
            }

            if file.hasSuffix(".hashes.txt") {
                _ = try? loadCustomFile(path: path, type: .hash)
            } else if file.hasSuffix(".ips.txt") {
                _ = try? loadCustomFile(path: path, type: .ip)
            } else if file.hasSuffix(".domains.txt") {
                _ = try? loadCustomFile(path: path, type: .domain)
            } else if file.hasSuffix(".urls.txt") {
                // v1.21.4 (audit): the app's custom-IOC UI already writes
                // custom.urls.txt and offers the URLs option, but this loader
                // never consumed it — the URL IOCs were silently ignored.
                _ = try? loadCustomFile(path: path, type: .url)
            }
        }
    }

    fileprivate struct CacheData: Codable {
        let hashes: [IOCRecord]
        let ips: [IOCRecord]
        let domains: [IOCRecord]
        let urls: [IOCRecord]
        let lastUpdate: Date?
        let lastSuccessfulPull: Date?
        let perFeedLastUpdate: [String: Date]?
        let perFeedLastError: [String: FeedError]?
    }
}
