// MCPBehavioralBaseline.swift
// MacCrabCore
//
// MCP server behavioral baseline. Every MCP server gets a fingerprint
// of what it does at runtime — file paths it touches, DNS domains it
// resolves, and child-process basenames it spawns. On first encounter
// the service is in `learning` mode for a configurable window; after
// that it switches to comparison mode. Novel observations become bounded
// pending candidates; they never add themselves to the accepted fingerprint.
// Production defaults to shadow mode until this heuristic has an evaluation
// corpus and an explicit operator-promotion workflow.
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
// Accepted/pending state is process-local. A versioned, freshness-bounded
// snapshot exists for dashboard observability, but is deliberately not restored
// as trusted state on boot. The service exposes an observation API that the
// EventLoop calls for attributed MCP-host activity. Only explicit review-alert
// mode publishes the bounded candidate stream; production defaults to shadow.

import Foundation
import os.log

// MARK: - MCPServerBaseline

public struct MCPServerBaseline: Sendable, Hashable, Codable {
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

/// Novel values observed after learning. Pending values are deliberately
/// separate from the accepted baseline so one anomalous call cannot authorize
/// itself for every future call.
public struct MCPPendingServerBaseline: Sendable, Hashable, Codable {
    public let serverKey: String
    public internal(set) var fileBasenames: Set<String>
    public internal(set) var domains: Set<String>
    public internal(set) var childBasenames: Set<String>
    public internal(set) var firstSeen: Date
    public internal(set) var lastSeen: Date
    public internal(set) var observationCount: Int

    public init(
        serverKey: String,
        fileBasenames: Set<String> = [],
        domains: Set<String> = [],
        childBasenames: Set<String> = [],
        firstSeen: Date,
        lastSeen: Date,
        observationCount: Int = 0
    ) {
        self.serverKey = serverKey
        self.fileBasenames = fileBasenames
        self.domains = domains
        self.childBasenames = childBasenames
        self.firstSeen = firstSeen
        self.lastSeen = lastSeen
        self.observationCount = observationCount
    }

    public var distinctValueCount: Int {
        fileBasenames.count + domains.count + childBasenames.count
    }
}

public enum MCPBaselineOperatingMode: String, Sendable, Codable, Hashable {
    /// Record bounded candidates and telemetry, but publish no security alert.
    case shadow
    /// Publish review-only deviations. This is opt-in and still never promotes
    /// a candidate automatically.
    case reviewAlerts = "review_alerts"
}

public struct MCPBaselineTelemetry: Sendable, Equatable {
    public let mode: MCPBaselineOperatingMode
    public let observationsTotal: UInt64
    public let shadowCandidatesTotal: UInt64
    public let publicationAttemptsTotal: UInt64
    public let publishedCandidatesTotal: UInt64
    public let publicationBufferEvictionsTotal: UInt64
    public let publicationTerminationsTotal: UInt64
    public let pendingCapacityRejectionsTotal: UInt64
    public let acceptedBaselines: Int
    public let pendingBaselines: Int
    public let pendingValues: Int
    public let largestAcceptedFamily: Int
    public let largestPendingFamily: Int
    public let maximumBaselines: Int
    public let maximumValuesPerFamily: Int

    public var capacityRespected: Bool {
        acceptedBaselines <= maximumBaselines
            && pendingBaselines <= maximumBaselines
            && largestAcceptedFamily <= maximumValuesPerFamily
            && largestPendingFamily <= maximumValuesPerFamily
    }

    public var publicationConserved: Bool {
        publicationAttemptsTotal
            == publishedCandidatesTotal &+ publicationTerminationsTotal
            && publicationBufferEvictionsTotal <= publishedCandidatesTotal
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
    /// `learning` to comparison-ready. Low enough that ordinary MCP use
    /// produces a useful shadow profile in minutes. Learning values are not a
    /// trust grant and cannot authorize containment or suppress another rule.
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
    /// plausible developer setup. The 512-value ceiling bounds both the
    /// learning fingerprint and each pending family; neither set grants
    /// response authority.
    public static let defaultMaxBaselines = 256
    public static let defaultMaxFingerprintSetSize = 512

    private let learningObservations: Int
    private let learningWindow: TimeInterval
    private let maxBaselines: Int
    private let maxSetSize: Int
    private let operatingMode: MCPBaselineOperatingMode
    private let snapshotWriter: CoalescingSnapshotWriter<BaselineSnapshot>

    private var baselines: [String: MCPServerBaseline] = [:]
    private var pendingBaselines: [String: MCPPendingServerBaseline] = [:]
    private var observationsTotal: UInt64 = 0
    private var shadowCandidatesTotal: UInt64 = 0
    private var publicationAttemptsTotal: UInt64 = 0
    private var publishedCandidatesTotal: UInt64 = 0
    private var publicationBufferEvictionsTotal: UInt64 = 0
    private var publicationTerminationsTotal: UInt64 = 0
    private var pendingCapacityRejectionsTotal: UInt64 = 0

    public nonisolated let deviations: AsyncStream<BaselineDeviation>
    private var deviationContinuation: AsyncStream<BaselineDeviation>.Continuation?

    public init(
        learningObservations: Int = defaultLearningObservations,
        learningWindow: TimeInterval = defaultLearningWindow,
        maxBaselines: Int = defaultMaxBaselines,
        maxSetSize: Int = defaultMaxFingerprintSetSize,
        operatingMode: MCPBaselineOperatingMode = .shadow
    ) {
        self.learningObservations = learningObservations
        self.learningWindow = learningWindow
        self.maxBaselines = max(1, maxBaselines)
        // Floor at 1 so tests can exercise tight caps; production
        // callers pass `defaultMaxFingerprintSetSize=512`.
        self.maxSetSize = max(1, maxSetSize)
        self.operatingMode = operatingMode
        self.snapshotWriter = CoalescingSnapshotWriter(
            category: "mcp-baseline-snapshot",
            persistence: Self.persistSnapshot
        )
        var captured: AsyncStream<BaselineDeviation>.Continuation!
        self.deviations = AsyncStream(bufferingPolicy: .bufferingNewest(128)) {
            captured = $0
        }
        self.deviationContinuation = captured
    }

    // MARK: API

    /// Record an observation. Returns newly-created shadow candidates (zero or
    /// one per field). Only explicit `.reviewAlerts` mode publishes them to the
    /// deviations stream. Neither mode automatically accepts a candidate.
    @discardableResult
    public func observe(_ obs: MCPBaselineObservation) -> [BaselineDeviation] {
        increment(&observationsTotal)
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
                pendingBaselines.removeValue(forKey: oldest.serverKey)
                logger.notice("MCP baseline cap hit (\(self.baselines.count + 1) > \(self.maxBaselines)); evicted oldest server \(oldest.serverName)")
            }
        }

        var baseline = baselines[key] ?? MCPServerBaseline(
            serverKey: key, tool: obs.tool, serverName: obs.serverName,
            firstSeen: obs.timestamp, lastSeen: obs.timestamp
        )
        var pending = pendingBaselines[key] ?? MCPPendingServerBaseline(
            serverKey: key,
            firstSeen: obs.timestamp,
            lastSeen: obs.timestamp
        )
        var candidates: [BaselineDeviation] = []
        var touchedPending = false

        if let file = obs.filePath {
            let basename = (file as NSString).lastPathComponent
            if !basename.isEmpty {
                if baseline.state == .enforcing,
                   !baseline.fileBasenames.contains(basename) {
                    touchedPending = true
                    if !pending.fileBasenames.contains(basename) {
                        if pending.fileBasenames.count < maxSetSize {
                            pending.fileBasenames.insert(basename)
                            candidates.append(makeDeviation(
                                kind: .newFileBasename, baseline: baseline,
                                value: basename, timestamp: obs.timestamp
                            ))
                        } else {
                            // Fail closed at the storage boundary. Returning or
                            // publishing a value we cannot retain would let the
                            // same overflow value re-alert on every event.
                            increment(&pendingCapacityRejectionsTotal)
                        }
                    }
                } else if baseline.state == .learning,
                          baseline.fileBasenames.count < maxSetSize {
                    baseline.fileBasenames.insert(basename)
                }
            }
        }
        if let domain = obs.domain, !domain.isEmpty {
            let normalized = Self.normalizeDomain(domain)
            if normalized.isEmpty {
                // A punctuation/whitespace-only input is not a hostname and
                // must not occupy accepted or pending capacity.
            } else if baseline.state == .enforcing,
               !baseline.domains.contains(normalized) {
                touchedPending = true
                if !pending.domains.contains(normalized) {
                    if pending.domains.count < maxSetSize {
                        pending.domains.insert(normalized)
                        candidates.append(makeDeviation(
                            kind: .newDomain, baseline: baseline,
                            value: normalized, timestamp: obs.timestamp
                        ))
                    } else {
                        increment(&pendingCapacityRejectionsTotal)
                    }
                }
            } else if baseline.state == .learning,
                      baseline.domains.count < maxSetSize {
                baseline.domains.insert(normalized)
            }
        }
        if let child = obs.childProcessBasename, !child.isEmpty {
                if baseline.state == .enforcing,
                   !baseline.childBasenames.contains(child) {
                    touchedPending = true
                    if !pending.childBasenames.contains(child) {
                        if pending.childBasenames.count < maxSetSize {
                            pending.childBasenames.insert(child)
                            candidates.append(makeDeviation(
                                kind: .newChildBasename, baseline: baseline,
                                value: child, timestamp: obs.timestamp
                            ))
                        } else {
                            increment(&pendingCapacityRejectionsTotal)
                        }
                }
            } else if baseline.state == .learning,
                      baseline.childBasenames.count < maxSetSize {
                baseline.childBasenames.insert(child)
            }
        }

        baseline.lastSeen = obs.timestamp
        increment(&baseline.observationCount)
        promoteIfEligible(&baseline)

        baselines[key] = baseline
        if pending.distinctValueCount > 0 {
            if touchedPending {
                pending.lastSeen = obs.timestamp
                increment(&pending.observationCount)
            }
            pendingBaselines[key] = pending
        }

        for candidate in candidates {
            increment(&shadowCandidatesTotal)
            if operatingMode == .reviewAlerts {
                increment(&publicationAttemptsTotal)
                guard let continuation = deviationContinuation else {
                    increment(&publicationTerminationsTotal)
                    continue
                }
                switch continuation.yield(candidate) {
                case .enqueued:
                    increment(&publishedCandidatesTotal)
                case .dropped:
                    // bufferingNewest accepts this candidate and evicts the
                    // oldest buffered one. Keep both facts observable.
                    increment(&publishedCandidatesTotal)
                    increment(&publicationBufferEvictionsTotal)
                case .terminated:
                    increment(&publicationTerminationsTotal)
                @unknown default:
                    increment(&publicationTerminationsTotal)
                }
            }
        }
        return candidates
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

    public func pendingBaseline(
        for tool: String,
        serverName: String
    ) -> MCPPendingServerBaseline? {
        pendingBaselines["\(tool)::\(serverName)"]
    }

    /// Explicit promotion seam for a future authenticated operator workflow.
    /// Values beyond the accepted-family cap remain pending; nothing is silently
    /// discarded or auto-authorized.
    @discardableResult
    public func approvePending(tool: String, serverName: String) -> Bool {
        let key = "\(tool)::\(serverName)"
        guard var baseline = baselines[key],
              var pending = pendingBaselines[key] else { return false }
        var promotedAny = false

        func promote(_ pendingValues: inout Set<String>, into accepted: inout Set<String>) {
            for value in pendingValues.sorted() where accepted.count < maxSetSize {
                accepted.insert(value)
                pendingValues.remove(value)
                promotedAny = true
            }
        }
        promote(&pending.fileBasenames, into: &baseline.fileBasenames)
        promote(&pending.domains, into: &baseline.domains)
        promote(&pending.childBasenames, into: &baseline.childBasenames)
        baselines[key] = baseline
        if pending.distinctValueCount == 0 {
            pendingBaselines.removeValue(forKey: key)
        } else {
            pendingBaselines[key] = pending
        }
        return promotedAny
    }

    public func telemetry() -> MCPBaselineTelemetry {
        let largestAcceptedFamily = baselines.values.reduce(0) { largest, baseline in
            max(largest, max(
                baseline.fileBasenames.count,
                max(baseline.domains.count, baseline.childBasenames.count)
            ))
        }
        let largestPendingFamily = pendingBaselines.values.reduce(0) { largest, pending in
            max(largest, max(
                pending.fileBasenames.count,
                max(pending.domains.count, pending.childBasenames.count)
            ))
        }
        return MCPBaselineTelemetry(
            mode: operatingMode,
            observationsTotal: observationsTotal,
            shadowCandidatesTotal: shadowCandidatesTotal,
            publicationAttemptsTotal: publicationAttemptsTotal,
            publishedCandidatesTotal: publishedCandidatesTotal,
            publicationBufferEvictionsTotal: publicationBufferEvictionsTotal,
            publicationTerminationsTotal: publicationTerminationsTotal,
            pendingCapacityRejectionsTotal: pendingCapacityRejectionsTotal,
            acceptedBaselines: baselines.count,
            pendingBaselines: pendingBaselines.count,
            pendingValues: pendingBaselines.values.reduce(0) {
                $0 + $1.distinctValueCount
            },
            largestAcceptedFamily: largestAcceptedFamily,
            largestPendingFamily: largestPendingFamily,
            maximumBaselines: maxBaselines,
            maximumValuesPerFamily: maxSetSize
        )
    }

    // MARK: - Cross-process snapshot (sysext → app, v1.7.0)

    /// On-disk snapshot wrapper. The dashboard's `MCPActivityView`
    /// reads this file from `<supportDir>/mcp_baselines.json` to render
    /// the per-server activity panel. Daemon writes through
    /// `writeSnapshot(to:)`; app reads through `readSnapshot(at:)`.
    public struct BaselineSnapshot: Sendable, Codable {
        public static let currentSchemaVersion = 2

        public let schemaVersion: Int
        public let writtenAt: Date
        public let mode: MCPBaselineOperatingMode
        public let baselines: [MCPServerBaseline]
        public let pendingBaselines: [MCPPendingServerBaseline]

        public init(
            schemaVersion: Int = Self.currentSchemaVersion,
            writtenAt: Date,
            mode: MCPBaselineOperatingMode = .shadow,
            baselines: [MCPServerBaseline],
            pendingBaselines: [MCPPendingServerBaseline] = []
        ) {
            self.schemaVersion = schemaVersion
            self.writtenAt = writtenAt
            self.mode = mode
            self.baselines = baselines
            self.pendingBaselines = pendingBaselines
        }

        private enum CodingKeys: String, CodingKey {
            case schemaVersion, writtenAt, mode, baselines, pendingBaselines
        }

        public init(from decoder: Decoder) throws {
            let values = try decoder.container(keyedBy: CodingKeys.self)
            schemaVersion = try values.decodeIfPresent(
                Int.self, forKey: .schemaVersion
            ) ?? 1
            writtenAt = try values.decode(Date.self, forKey: .writtenAt)
            mode = try values.decodeIfPresent(
                MCPBaselineOperatingMode.self, forKey: .mode
            ) ?? .shadow
            baselines = try values.decode(
                [MCPServerBaseline].self, forKey: .baselines
            )
            pendingBaselines = try values.decodeIfPresent(
                [MCPPendingServerBaseline].self,
                forKey: .pendingBaselines
            ) ?? []
        }
    }

    /// Snapshot assembly stays on this actor; encoding and descriptor-safe
    /// publication run through the shared one-active/one-latest writer so a
    /// slow disk cannot stall `observe` or retain unbounded full snapshots.
    public func writeSnapshot(to path: String) async {
        let snapshot = BaselineSnapshot(
            writtenAt: Date(),
            mode: operatingMode,
            baselines: allBaselines(),
            pendingBaselines: pendingBaselines.values.sorted {
                $0.lastSeen > $1.lastSeen
            }
        )
        await snapshotWriter.publish(snapshot, to: path)
    }

    public func snapshotWriteTelemetry() async -> CoalescingSnapshotWriterTelemetry {
        await snapshotWriter.telemetry()
    }

    @Sendable
    private nonisolated static func persistSnapshot(
        _ snapshot: BaselineSnapshot,
        to path: String
    ) -> String? {
        do {
            let data = try JSONEncoder().encode(snapshot)
            try SecureFileIO.atomicReplace(at: path, data: data, mode: 0o640)
            // 0o640, not 0o644 — same class as the AgentLineageService Sec-H1
            // fix. This snapshot is a per-MCP-server behavioural profile (which
            // AI tooling this operator runs, and how it behaves), and at 0o644
            // any local unprivileged process could read it. The dashboard
            // (V2LiveDataProvider) reads it as an admin-group uid-501 process,
            // which 0o640 root:admin still permits.
            try? FileManager.default.setAttributes(
                [.posixPermissions: 0o640, .groupOwnerAccountID: 80],
                ofItemAtPath: path
            )
            return nil
        } catch {
            return String(error.localizedDescription.prefix(512))
        }
    }

    /// Read a snapshot from disk. Used by the dashboard to populate
    /// `AppState.mcpBaselines` without crossing the privilege boundary.
    public nonisolated static func readSnapshot(at path: String) -> BaselineSnapshot? {
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)) else { return nil }
        return try? JSONDecoder().decode(BaselineSnapshot.self, from: data)
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
        pendingBaselines.removeValue(forKey: key)
    }

    /// Wipe every baseline. Exposed for tests and for operator use.
    public func resetAll() {
        baselines.removeAll()
        pendingBaselines.removeAll()
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

    /// Canonicalize a host without inventing registrable-domain semantics.
    /// Last-two-label heuristics collapse unrelated tenants such as
    /// `victim.github.io` and `attacker.github.io`; exact hosts are the safe
    /// contract until MacCrab ships a versioned Public Suffix List parser.
    static func normalizeDomain(_ domain: String) -> String {
        domain.lowercased()
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .trimmingCharacters(in: CharacterSet(charactersIn: "."))
    }

    private func increment(_ value: inout UInt64) {
        if value < UInt64.max { value += 1 }
    }

    private func increment(_ value: inout Int) {
        if value < Int.max { value += 1 }
    }
}
