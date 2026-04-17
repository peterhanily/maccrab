// CrossProcessCorrelator.swift
// MacCrabCore
//
// Connects events across unrelated process trees by shared artifacts:
// files, network destinations, and domains. When Process A downloads a
// file, Process B executes it, and Process C reaches out to a C2 server,
// these form a single attack chain even though the processes share no
// lineage. This engine discovers those chains in real time.

import Foundation
import os.log

/// Correlates events across process boundaries using shared artifacts.
///
/// Unlike `IncidentGrouper` (which clusters alerts within the same process
/// tree), this actor links *unrelated* process trees that touch the same
/// file, network destination, or domain within a sliding time window.
///
/// **Typical chain:** curl writes `/tmp/payload` → bash executes `/tmp/payload`
/// → payload connects to 198.51.100.7:443.  Three different process trees,
/// one attack chain.
public actor CrossProcessCorrelator {

    private let logger = Logger(subsystem: "com.maccrab", category: "cross-process")

    // MARK: - Types

    /// The kind of artifact that links events together.
    private enum ArtifactType: Hashable, Sendable {
        case filePath(String)
        case networkDestination(String)   // "ip:port"
        case domainDestination(String)
    }

    /// A single event in a cross-process correlation chain.
    public struct ChainEvent: Sendable {
        public let timestamp: Date
        public let pid: Int32
        public let processName: String
        public let processPath: String
        public let action: String   // "download", "write", "execute", "connect", "read"

        public init(
            timestamp: Date,
            pid: Int32,
            processName: String,
            processPath: String,
            action: String
        ) {
            self.timestamp = timestamp
            self.pid = pid
            self.processName = processName
            self.processPath = processPath
            self.action = action
        }
    }

    /// A completed correlation chain spanning multiple processes.
    public struct CorrelationChain: Sendable {
        public let id: String
        public let events: [ChainEvent]
        public let sharedArtifact: String
        public let artifactType: String   // "file", "network", "domain"
        public let timeSpanSeconds: Double
        public let processCount: Int
        public let severity: Severity
        public let description: String
    }

    // MARK: - Configuration

    /// Maximum elapsed time between first and last event for correlation.
    private let correlationWindow: TimeInterval

    /// Minimum number of events (from different PIDs) to form a chain.
    private let minChainLength: Int

    /// Maximum number of distinct artifacts tracked per map before eviction.
    private let maxArtifactsPerMap: Int = 10_000

    // MARK: - State

    /// File path -> ordered list of events touching that path.
    private var fileArtifacts: [String: [ChainEvent]] = [:]

    /// "ip:port" -> ordered list of events contacting that destination.
    private var networkArtifacts: [String: [ChainEvent]] = [:]

    /// Domain name -> ordered list of events resolving/contacting that domain.
    private var domainArtifacts: [String: [ChainEvent]] = [:]

    /// Tracks when we last ran a purge pass, to avoid purging on every call.
    private var lastPurge: Date

    // MARK: - Noise-reduction sets

    /// System paths that many processes legitimately touch.
    private static let ignoredPathPrefixes: [String] = [
        "/System/",
        "/usr/lib/",
        "/usr/share/",
        "/Library/Apple/",
        "/private/var/db/dyld/",
    ]

    /// Specific paths that are never interesting for correlation.
    private static let ignoredPaths: Set<String> = [
        "/dev/null",
        "/dev/urandom",
        "/dev/random",
        "/dev/zero",
    ]

    /// Network destinations that are never interesting.
    private static let ignoredNetworkPrefixes: [String] = [
        "127.",            // loopback
        "0.0.0.0",
        "::1",
        "169.254.",        // link-local
        "fe80:",           // link-local v6
    ]

    /// Destinations served by well-known cloud / AI-service CDNs. Multiple
    /// processes hitting one of these is almost always a legitimate tool
    /// family (Claude Code + its node MCP helpers + its cli wrapper, for
    /// example) — not attacker convergence. These ranges mirror the AI
    /// network sandbox allowlist so the two stay in sync.
    private static let trustedCloudPrefixes: [String] = [
        // Anthropic (Fastly)
        "160.79.",
        // OpenAI / Cloudflare-fronted services
        "104.16.", "104.17.", "104.18.", "104.19.", "104.20.", "104.21.", "104.22.",
        "172.64.", "172.65.", "172.66.", "172.67.",
        // Google / GCP / Gemini (mirrors the AI-sandbox Google IP list so
        // the two stay in sync — see https://www.gstatic.com/ipranges/goog.json)
        "34.96.", "34.97.", "34.98.", "34.99.", "34.149.", "34.150.",
        "35.186.", "35.187.", "35.188.", "35.189.", "35.190.", "35.191.",
        "64.233.", "66.102.", "66.249.",
        "72.14.",
        "74.125.",
        "108.177.",
        "142.250.", "142.251.",
        "172.217.", "172.253.",
        "173.194.",
        "209.85.",
        "216.58.", "216.239.",
        // GitHub / Copilot
        "140.82.", "185.199.",
        // Cloudflare
        "162.159.", "141.101.", "108.162.",
    ]

    /// Destination domains served by trusted APIs. Used when the chain key
    /// is domain-based rather than IP-based.
    private static let trustedCloudDomains: [String] = [
        "anthropic.com", "claude.ai",
        "openai.com", "chatgpt.com", "oaiusercontent.com",
        "github.com", "githubusercontent.com", "githubassets.com",
        "google.com", "googleapis.com", "gstatic.com",
        "cloudflare.com", "cloudflare-dns.com",
        "apple.com", "icloud.com", "mzstatic.com",
    ]

    // MARK: - Initialization

    /// Creates a new cross-process correlator.
    ///
    /// - Parameters:
    ///   - correlationWindow: Maximum time span (seconds) for events to be
    ///     considered part of the same chain. Defaults to 300 (5 minutes).
    ///   - minChainLength: Minimum number of events from different PIDs
    ///     required to emit a chain. Defaults to 3 (reduces noise from
    ///     normal multi-process traffic like browsers + git to same CDN).
    public init(correlationWindow: TimeInterval = 300, minChainLength: Int = 3) {
        self.correlationWindow = correlationWindow
        self.minChainLength = minChainLength
        self.lastPurge = Date()
    }

    // MARK: - Public API

    /// Record a file event (write, execute, read, download, create).
    ///
    /// Returns a correlation chain if this event completes a cross-process
    /// chain involving the same file path.
    @discardableResult
    public func recordFileEvent(
        path: String,
        action: String,
        pid: Int32,
        processName: String,
        processPath: String,
        timestamp: Date = Date()
    ) -> CorrelationChain? {
        guard !shouldIgnoreFilePath(path) else { return nil }

        let event = ChainEvent(
            timestamp: timestamp,
            pid: pid,
            processName: processName,
            processPath: processPath,
            action: action
        )

        fileArtifacts[path, default: []].append(event)
        purgeIfNeeded()

        return evaluateFileChain(path: path)
    }

    /// Record a network event (connect, DNS lookup).
    ///
    /// Returns a correlation chain if this event completes a cross-process
    /// chain involving the same destination.
    @discardableResult
    public func recordNetworkEvent(
        destinationIP: String,
        destinationPort: UInt16,
        destinationDomain: String? = nil,
        pid: Int32,
        processName: String,
        processPath: String,
        timestamp: Date = Date()
    ) -> CorrelationChain? {
        guard !shouldIgnoreNetworkDestination(destinationIP) else { return nil }

        let event = ChainEvent(
            timestamp: timestamp,
            pid: pid,
            processName: processName,
            processPath: processPath,
            action: "connect"
        )

        let ipKey = "\(destinationIP):\(destinationPort)"
        networkArtifacts[ipKey, default: []].append(event)

        var chain = evaluateNetworkChain(key: ipKey, artifactType: "network")

        // Also track by domain if provided.
        if let domain = destinationDomain, !domain.isEmpty {
            domainArtifacts[domain, default: []].append(event)
            if chain == nil {
                chain = evaluateNetworkChain(key: domain, artifactType: "domain")
            }
        }

        purgeIfNeeded()
        return chain
    }

    /// Remove all artifacts whose most recent event is older than the
    /// correlation window. Call periodically to bound memory.
    public func purgeStale() {
        let cutoff = Date().addingTimeInterval(-correlationWindow)

        fileArtifacts = purgeArtifactMap(fileArtifacts, cutoff: cutoff)
        networkArtifacts = purgeArtifactMap(networkArtifacts, cutoff: cutoff)
        domainArtifacts = purgeArtifactMap(domainArtifacts, cutoff: cutoff)

        // Enforce hard cap per map: evict oldest artifacts if still over limit
        fileArtifacts = evictIfOverLimit(fileArtifacts)
        networkArtifacts = evictIfOverLimit(networkArtifacts)
        domainArtifacts = evictIfOverLimit(domainArtifacts)

        lastPurge = Date()
        logger.debug("Purge complete — files: \(self.fileArtifacts.count), network: \(self.networkArtifacts.count), domains: \(self.domainArtifacts.count)")
    }

    // MARK: - Diagnostics

    /// Number of distinct file artifacts currently tracked.
    public var trackedFileCount: Int { fileArtifacts.count }

    /// Number of distinct network artifacts currently tracked.
    public var trackedNetworkCount: Int { networkArtifacts.count }

    /// Number of distinct domain artifacts currently tracked.
    public var trackedDomainCount: Int { domainArtifacts.count }

    /// Total number of individual events stored across all artifact maps.
    public var totalEventCount: Int {
        fileArtifacts.values.reduce(0) { $0 + $1.count }
            + networkArtifacts.values.reduce(0) { $0 + $1.count }
            + domainArtifacts.values.reduce(0) { $0 + $1.count }
    }

    // MARK: - Chain Evaluation

    /// Evaluate whether the events for a given file path form a complete chain.
    private func evaluateFileChain(path: String) -> CorrelationChain? {
        guard let events = fileArtifacts[path] else { return nil }

        // Filter to events within the correlation window.
        let windowEvents = eventsWithinWindow(events)

        // Must involve multiple distinct PIDs.
        let distinctPIDs = Set(windowEvents.map(\.pid))
        guard distinctPIDs.count >= minChainLength else { return nil }

        // Must span different action types (write+execute, not just write+write).
        let actions = Set(windowEvents.map(\.action))
        guard actions.count >= 2 else { return nil }

        let severity = computeFileSeverity(events: windowEvents, actions: actions)
        let chain = buildChain(
            events: windowEvents,
            artifact: path,
            artifactType: "file",
            severity: severity
        )

        logger.warning(
            "Cross-process file chain detected: \(chain.description) [\(chain.severity.rawValue)]"
        )
        return chain
    }

    /// Evaluate whether the events for a given network key form a complete chain.
    private func evaluateNetworkChain(key: String, artifactType: String) -> CorrelationChain? {
        let events: [ChainEvent]
        if artifactType == "domain" {
            guard let stored = domainArtifacts[key] else { return nil }
            events = stored
        } else {
            guard let stored = networkArtifacts[key] else { return nil }
            events = stored
        }

        let windowEvents = eventsWithinWindow(events)

        // Must involve multiple distinct PIDs.
        let distinctPIDs = Set(windowEvents.map(\.pid))
        guard distinctPIDs.count >= minChainLength else { return nil }

        // Skip when the destination is a well-known cloud/AI service CDN.
        // Multi-process fan-out to Anthropic / OpenAI / Google / GitHub is
        // expected when a developer has several AI tools running: the cli
        // wrapper, a node MCP helper, and an IDE plugin all talk to the same
        // backend. Flagging that as "convergence" produced the overwhelming
        // majority of false positives on real dev workstations.
        if destinationIsTrustedCloud(key: key, artifactType: artifactType) { return nil }

        // Skip "convergence" events where every contacting process lives in
        // the same application bundle. Electron / Chromium apps routinely
        // spawn 5+ helper processes that all hit the same Google / Slack /
        // GitHub endpoint — that's architecture, not attack.
        if allEventsShareAppBundle(windowEvents) { return nil }
        // Also skip when every process is the same executable (e.g. multiple
        // `node` instances making concurrent API calls) or lives in the same
        // tool-version directory (e.g. Claude Code forks under
        // `.local/share/claude/versions/<ver>/`). A tool calling itself in
        // parallel isn't a convergence event.
        if allEventsShareExecutable(windowEvents) { return nil }
        if allEventsShareToolDirectory(windowEvents) { return nil }

        let severity = computeNetworkSeverity(events: windowEvents)
        let chain = buildChain(
            events: windowEvents,
            artifact: key,
            artifactType: artifactType,
            severity: severity
        )

        logger.warning(
            "Cross-process \(artifactType) convergence: \(chain.description) [\(chain.severity.rawValue)]"
        )
        return chain
    }

    /// True when the artifact key (ip:port or domain) belongs to a trusted
    /// cloud / AI-service provider. Called before per-event-process filters
    /// because the destination is a much stronger noise signal: if the
    /// target is Anthropic or Google, multi-process fan-out to that target
    /// is architecture regardless of which local processes are involved.
    private func destinationIsTrustedCloud(key: String, artifactType: String) -> Bool {
        if artifactType == "network" {
            // key format: "ip:port"
            let ip = key.split(separator: ":").first.map(String.init) ?? key
            for prefix in Self.trustedCloudPrefixes where ip.hasPrefix(prefix) {
                return true
            }
        } else if artifactType == "domain" {
            let lower = key.lowercased()
            for suffix in Self.trustedCloudDomains where lower.hasSuffix(suffix) {
                return true
            }
        }
        return false
    }

    /// True when every event's process lives under the same `.app` bundle.
    private func allEventsShareAppBundle(_ events: [ChainEvent]) -> Bool {
        var bundles: Set<String> = []
        for event in events {
            guard let bundle = appBundleRoot(for: event.processPath) else { return false }
            bundles.insert(bundle)
            if bundles.count > 1 { return false }
        }
        return bundles.count == 1
    }

    /// True when every event is the same executable (same path).
    private func allEventsShareExecutable(_ events: [ChainEvent]) -> Bool {
        guard let first = events.first else { return false }
        return events.allSatisfy { $0.processPath == first.processPath }
    }

    /// True when every event's process lives under the same tool-version
    /// directory — i.e. the parent directory of the executable matches, or
    /// they share a common ancestor that looks like `/versions/<ver>`.
    /// Catches cases like Claude Code forking several processes under
    /// `~/.local/share/claude/versions/2.1.111/` where there's no `.app`.
    private func allEventsShareToolDirectory(_ events: [ChainEvent]) -> Bool {
        guard let first = events.first else { return false }
        let firstDir = (first.processPath as NSString).deletingLastPathComponent
        return events.allSatisfy {
            ($0.processPath as NSString).deletingLastPathComponent == firstDir
        }
    }

    /// Returns the outermost `.app/` directory for an executable path, or nil
    /// if the path isn't inside an app bundle.
    private func appBundleRoot(for path: String) -> String? {
        guard let range = path.range(of: ".app/") else { return nil }
        return String(path[path.startIndex..<range.upperBound])
    }

    // MARK: - Severity Calculation

    /// Compute severity for a file-based chain.
    ///
    /// - 2 events, file only: medium
    /// - 2+ events with both file and network actions: high
    /// - 3+ events spanning write -> execute -> network: critical
    private func computeFileSeverity(events: [ChainEvent], actions: Set<String>) -> Severity {
        let hasWrite = actions.contains("write") || actions.contains("download")
        let hasExecute = actions.contains("execute")
        let hasNetwork = actions.contains("connect")
        let distinctPIDs = Set(events.map(\.pid)).count

        // 3+ events spanning write -> execute -> network: critical
        if distinctPIDs >= 3, hasWrite, hasExecute, hasNetwork {
            return .critical
        }

        // 2+ events with both file and network
        if hasNetwork, (hasWrite || hasExecute) {
            return .high
        }

        // write -> execute by different process
        if hasWrite, hasExecute {
            return .high
        }

        // Baseline: two processes touching the same file with different actions
        return .medium
    }

    /// Compute severity for a network-based chain (multiple unrelated processes
    /// contacting the same destination).
    private func computeNetworkSeverity(events: [ChainEvent]) -> Severity {
        let distinctPIDs = Set(events.map(\.pid)).count

        if distinctPIDs >= 3 {
            return .high
        }
        return .medium
    }

    // MARK: - Chain Construction

    /// Build a `CorrelationChain` from a set of events.
    private func buildChain(
        events: [ChainEvent],
        artifact: String,
        artifactType: String,
        severity: Severity
    ) -> CorrelationChain {
        let sorted = events.sorted { $0.timestamp < $1.timestamp }
        let firstTime = sorted.first?.timestamp ?? Date()
        let lastTime = sorted.last?.timestamp ?? Date()
        let span = lastTime.timeIntervalSince(firstTime)
        let distinctPIDs = Set(sorted.map(\.pid))
        let processNames = Set(sorted.map(\.processName))

        let desc: String
        switch artifactType {
        case "file":
            let actions = sorted.map(\.action).joined(separator: " -> ")
            desc = "\(processNames.sorted().joined(separator: ", ")) touched \(artifact) [\(actions)] over \(Int(span))s"
        case "network":
            desc = "\(distinctPIDs.count) unrelated processes contacted \(artifact) over \(Int(span))s"
        case "domain":
            desc = "\(distinctPIDs.count) unrelated processes resolved \(artifact) over \(Int(span))s"
        default:
            desc = "\(distinctPIDs.count) processes share artifact \(artifact)"
        }

        return CorrelationChain(
            id: "XPROC-\(UUID().uuidString.prefix(8))",
            events: sorted,
            sharedArtifact: artifact,
            artifactType: artifactType,
            timeSpanSeconds: span,
            processCount: distinctPIDs.count,
            severity: severity,
            description: desc
        )
    }

    // MARK: - Filtering Helpers

    /// Whether a file path should be ignored for correlation (system noise).
    private func shouldIgnoreFilePath(_ path: String) -> Bool {
        if Self.ignoredPaths.contains(path) { return true }
        for prefix in Self.ignoredPathPrefixes {
            if path.hasPrefix(prefix) { return true }
        }
        return false
    }

    /// Whether a network destination should be ignored (localhost, link-local).
    private func shouldIgnoreNetworkDestination(_ ip: String) -> Bool {
        for prefix in Self.ignoredNetworkPrefixes {
            if ip.hasPrefix(prefix) { return true }
        }
        return false
    }

    /// Return only events within the correlation window relative to the most
    /// recent event in the list.
    private func eventsWithinWindow(_ events: [ChainEvent]) -> [ChainEvent] {
        guard let latest = events.max(by: { $0.timestamp < $1.timestamp }) else {
            return []
        }
        let cutoff = latest.timestamp.addingTimeInterval(-correlationWindow)
        return events.filter { $0.timestamp >= cutoff }
    }

    // MARK: - Purge Helpers

    /// Purge stale entries from an artifact map.
    private func purgeArtifactMap(
        _ map: [String: [ChainEvent]],
        cutoff: Date
    ) -> [String: [ChainEvent]] {
        var result: [String: [ChainEvent]] = [:]
        for (key, events) in map {
            let live = events.filter { $0.timestamp >= cutoff }
            if !live.isEmpty {
                result[key] = live
            }
        }
        return result
    }

    /// Evict the oldest artifacts if the map exceeds `maxArtifactsPerMap`.
    /// "Oldest" is determined by the most recent event timestamp in each artifact's list.
    private func evictIfOverLimit(
        _ map: [String: [ChainEvent]]
    ) -> [String: [ChainEvent]] {
        guard map.count > maxArtifactsPerMap else { return map }

        // Sort by newest event timestamp (ascending) and keep only the most recent entries
        let sorted = map.sorted { lhs, rhs in
            let lhsLatest = lhs.value.max(by: { $0.timestamp < $1.timestamp })?.timestamp ?? .distantPast
            let rhsLatest = rhs.value.max(by: { $0.timestamp < $1.timestamp })?.timestamp ?? .distantPast
            return lhsLatest < rhsLatest
        }
        let toKeep = sorted.suffix(maxArtifactsPerMap)
        let evicted = map.count - maxArtifactsPerMap
        logger.warning("Evicted \(evicted) oldest artifact entries to enforce \(self.maxArtifactsPerMap) cap")
        return Dictionary(uniqueKeysWithValues: toKeep.map { ($0.key, $0.value) })
    }

    /// Run a purge pass if enough time has elapsed since the last one
    /// (at most once per 30 seconds).
    private func purgeIfNeeded() {
        let now = Date()
        if now.timeIntervalSince(lastPurge) > 30 {
            purgeStale()
        }
    }
}
