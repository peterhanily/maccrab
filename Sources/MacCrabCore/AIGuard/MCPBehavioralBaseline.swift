// MCPBehavioralBaseline.swift
// MacCrabCore
//
// MCP server behavioral baseline. Every MCP server gets a fingerprint
// of what it does at runtime — file paths it touches, DNS domains it
// resolves, and child-process basenames it spawns. On first encounter
// the service is in `learning` mode for a configurable window; after
// that it switches to `enforcing`, and any observation outside the
// fingerprint produces a `BaselineDeviation`.
//
// This complements the existing `MCPMonitor`, which watches config
// files for *static* drift ("a new server was added"). Static config
// scans miss the real attack: an MCP server whose config is stable
// but whose behavior is quietly getting wider. Prompt-injectable MCP
// servers are the growth vector — Claude Desktop, Cursor, Claude Code,
// Continue, and VS Code MCP hosts all run servers with full user
// privileges, and nothing else in the macOS ecosystem tracks per-
// server runtime behavior.
//
// Scope for v1.6.6: in-memory state only (no cross-daemon persistence
// yet; that's v1.6.7). The service exposes an observation API that
// the EventLoop calls whenever an event attributable to an MCP host
// tree comes through. Deviations emit via an AsyncStream so they
// route through the existing alert pipeline.

import Foundation
import os.log

// MARK: - MCPServerBaseline

public struct MCPServerBaseline: Sendable, Hashable {
    public let serverKey: String           // "<tool>::<serverName>"
    public let tool: String                // claude | cursor | vscode | …
    public let serverName: String
    public internal(set) var fileBasenames: Set<String>
    public internal(set) var domains: Set<String>
    public internal(set) var childBasenames: Set<String>
    public internal(set) var firstSeen: Date
    public internal(set) var lastSeen: Date
    public internal(set) var state: BaselineState
    public internal(set) var observationCount: Int

    public enum BaselineState: String, Sendable, Hashable, Codable {
        case learning
        case enforcing
    }

    public init(serverKey: String, tool: String, serverName: String,
                fileBasenames: Set<String> = [], domains: Set<String> = [],
                childBasenames: Set<String> = [],
                firstSeen: Date = Date(), lastSeen: Date = Date(),
                state: BaselineState = .learning, observationCount: Int = 0) {
        self.serverKey = serverKey
        self.tool = tool
        self.serverName = serverName
        self.fileBasenames = fileBasenames
        self.domains = domains
        self.childBasenames = childBasenames
        self.firstSeen = firstSeen
        self.lastSeen = lastSeen
        self.state = state
        self.observationCount = observationCount
    }
}

// MARK: - MCPBaselineObservation

public struct MCPBaselineObservation: Sendable, Hashable {
    public let tool: String
    public let serverName: String
    public let filePath: String?
    public let domain: String?
    public let childProcessBasename: String?
    public let timestamp: Date

    public init(tool: String, serverName: String,
                filePath: String? = nil, domain: String? = nil,
                childProcessBasename: String? = nil,
                timestamp: Date = Date()) {
        self.tool = tool
        self.serverName = serverName
        self.filePath = filePath
        self.domain = domain
        self.childProcessBasename = childProcessBasename
        self.timestamp = timestamp
    }

    public var serverKey: String { "\(tool)::\(serverName)" }
}

// MARK: - BaselineDeviation

public struct BaselineDeviation: Sendable, Hashable {
    public enum Kind: String, Sendable, Hashable, Codable {
        case newFileBasename = "new_file_basename"
        case newDomain = "new_domain"
        case newChildBasename = "new_child_process"
    }

    public let kind: Kind
    public let serverKey: String
    public let tool: String
    public let serverName: String
    public let observedValue: String
    public let observationTimestamp: Date

    public init(kind: Kind, serverKey: String, tool: String, serverName: String,
                observedValue: String, observationTimestamp: Date) {
        self.kind = kind
        self.serverKey = serverKey
        self.tool = tool
        self.serverName = serverName
        self.observedValue = observedValue
        self.observationTimestamp = observationTimestamp
    }
}

// MARK: - MCPBaselineService

public actor MCPBaselineService {
    private let logger = Logger(subsystem: "com.maccrab.aiguard", category: "mcp-baseline")

    /// How many observations a server logs before we promote it from
    /// `learning` to `enforcing`. Low enough that casual MCP use
    /// produces a baseline in minutes; high enough that a single
    /// malicious call during learning gets absorbed rather than
    /// fingerprinted as "normal".
    public static let defaultLearningObservations = 20

    /// Minimum wall-clock window a server must spend in `learning`
    /// before promotion. Prevents a burst of 20 calls in 2s from
    /// instantly locking the baseline — real usage stretches across
    /// minutes.
    public static let defaultLearningWindow: TimeInterval = 300  // 5 min

    /// v1.6.9 DoS hardening: hard caps on how many distinct baselines
    /// we track and how large each baseline's fingerprint sets can
    /// grow. Without these, a malicious MCP-attributable process can
    /// spoof `serverName` per call and drive unbounded heap growth.
    /// Conservative defaults — 256 servers is ~100x more than a
    /// plausible developer setup, and 512 distinct values per set
    /// captures the long tail of a legitimate server without being a
    /// useful oracle for an attacker.
    public static let defaultMaxBaselines = 256
    public static let defaultMaxFingerprintSetSize = 512

    private let learningObservations: Int
    private let learningWindow: TimeInterval
    private let maxBaselines: Int
    private let maxSetSize: Int

    private var baselines: [String: MCPServerBaseline] = [:]

    public nonisolated let deviations: AsyncStream<BaselineDeviation>
    private var deviationContinuation: AsyncStream<BaselineDeviation>.Continuation?

    public init(
        learningObservations: Int = defaultLearningObservations,
        learningWindow: TimeInterval = defaultLearningWindow,
        maxBaselines: Int = defaultMaxBaselines,
        maxSetSize: Int = defaultMaxFingerprintSetSize
    ) {
        self.learningObservations = learningObservations
        self.learningWindow = learningWindow
        self.maxBaselines = max(1, maxBaselines)
        // Floor at 1 so tests can exercise tight caps; production
        // callers pass `defaultMaxFingerprintSetSize=512`.
        self.maxSetSize = max(1, maxSetSize)
        var captured: AsyncStream<BaselineDeviation>.Continuation!
        self.deviations = AsyncStream(bufferingPolicy: .bufferingNewest(128)) {
            captured = $0
        }
        self.deviationContinuation = captured
    }

    // MARK: API

    /// Record an observation. Returns the deviations (zero or one per
    /// observed field) that the service emitted. The service also
    /// broadcasts the deviations via the `deviations` stream so
    /// downstream consumers (EventLoop, dashboard) can subscribe.
    @discardableResult
    public func observe(_ obs: MCPBaselineObservation) -> [BaselineDeviation] {
        let key = obs.serverKey

        // v1.6.9: before instantiating a NEW baseline, enforce the
        // per-service cap. If we're at the limit AND this would
        // create a new entry, evict the LRU (oldest `lastSeen`)
        // first. A well-behaved MCP setup never hits the cap; a
        // rotating-serverName attack will churn the eviction list
        // but never exceed `maxBaselines`.
        if baselines[key] == nil, baselines.count >= maxBaselines {
            if let oldest = baselines.values.min(by: { $0.lastSeen < $1.lastSeen }) {
                baselines.removeValue(forKey: oldest.serverKey)
                logger.notice("MCP baseline cap hit (\(self.baselines.count + 1) > \(self.maxBaselines)); evicted oldest server \(oldest.serverName)")
            }
        }

        var baseline = baselines[key] ?? MCPServerBaseline(
            serverKey: key, tool: obs.tool, serverName: obs.serverName,
            firstSeen: obs.timestamp, lastSeen: obs.timestamp
        )
        var emitted: [BaselineDeviation] = []

        if let file = obs.filePath {
            let basename = (file as NSString).lastPathComponent
            if !basename.isEmpty {
                if !baseline.fileBasenames.contains(basename), baseline.state == .enforcing {
                    emitted.append(makeDeviation(
                        kind: .newFileBasename, baseline: baseline,
                        value: basename, timestamp: obs.timestamp
                    ))
                }
                if baseline.fileBasenames.count < maxSetSize {
                    baseline.fileBasenames.insert(basename)
                }
            }
        }
        if let domain = obs.domain, !domain.isEmpty {
            let normalized = Self.normalizeDomain(domain)
            if !baseline.domains.contains(normalized), baseline.state == .enforcing {
                emitted.append(makeDeviation(
                    kind: .newDomain, baseline: baseline,
                    value: normalized, timestamp: obs.timestamp
                ))
            }
            if baseline.domains.count < maxSetSize {
                baseline.domains.insert(normalized)
            }
        }
        if let child = obs.childProcessBasename, !child.isEmpty {
            if !baseline.childBasenames.contains(child), baseline.state == .enforcing {
                emitted.append(makeDeviation(
                    kind: .newChildBasename, baseline: baseline,
                    value: child, timestamp: obs.timestamp
                ))
            }
            if baseline.childBasenames.count < maxSetSize {
                baseline.childBasenames.insert(child)
            }
        }

        baseline.lastSeen = obs.timestamp
        baseline.observationCount += 1
        promoteIfEligible(&baseline)

        baselines[key] = baseline

        for deviation in emitted {
            deviationContinuation?.yield(deviation)
        }
        return emitted
    }

    /// Snapshot the current baseline for a server, or nil if unseen.
    public func baseline(for tool: String, serverName: String) -> MCPServerBaseline? {
        baselines["\(tool)::\(serverName)"]
    }

    /// All current baselines, for dashboard display. Order: most
    /// recently-active first.
    public func allBaselines() -> [MCPServerBaseline] {
        baselines.values.sorted { $0.lastSeen > $1.lastSeen }
    }

    /// Reset a single server's baseline back to learning. Used when
    /// the operator explicitly reconfigures a server — prevents a
    /// stale baseline from producing false deviations after a
    /// legitimate behavior change.
    public func reset(tool: String, serverName: String) {
        let key = "\(tool)::\(serverName)"
        guard var baseline = baselines[key] else { return }
        baseline.fileBasenames.removeAll()
        baseline.domains.removeAll()
        baseline.childBasenames.removeAll()
        baseline.state = .learning
        baseline.observationCount = 0
        baseline.firstSeen = Date()
        baseline.lastSeen = Date()
        baselines[key] = baseline
    }

    /// Wipe every baseline. Exposed for tests and for operator use.
    public func resetAll() {
        baselines.removeAll()
    }

    // MARK: Private helpers

    private func promoteIfEligible(_ baseline: inout MCPServerBaseline) {
        guard baseline.state == .learning else { return }
        let enoughObservations = baseline.observationCount >= learningObservations
        let enoughWallClock = baseline.lastSeen.timeIntervalSince(baseline.firstSeen) >= learningWindow
        if enoughObservations, enoughWallClock {
            baseline.state = .enforcing
        }
    }

    private func makeDeviation(
        kind: BaselineDeviation.Kind,
        baseline: MCPServerBaseline,
        value: String,
        timestamp: Date
    ) -> BaselineDeviation {
        BaselineDeviation(
            kind: kind,
            serverKey: baseline.serverKey,
            tool: baseline.tool,
            serverName: baseline.serverName,
            observedValue: value,
            observationTimestamp: timestamp
        )
    }

    /// Collapse `a.b.c.example.com`, `example.com`, and `www.example.com`
    /// to `example.com`. This is deliberately simple — a production-
    /// grade version would use the Public Suffix List; for a behavioral
    /// fingerprint, "same eTLD+1" is good enough and doesn't need the
    /// PSL dependency. A few over-collapses (e.g. `*.github.io` all
    /// landing on `github.io`) are acceptable for the baseline use case.
    static func normalizeDomain(_ domain: String) -> String {
        let lower = domain.lowercased()
            .trimmingCharacters(in: CharacterSet(charactersIn: ".:/ \n"))
        let labels = lower.split(separator: ".").map(String.init)
        if labels.count <= 2 { return lower }
        let tail = labels.suffix(2).joined(separator: ".")
        return tail
    }
}
