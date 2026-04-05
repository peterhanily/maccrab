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
