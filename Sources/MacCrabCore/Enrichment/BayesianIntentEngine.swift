// BayesianIntentEngine.swift
// MacCrabCore
//
// Lightweight Bayesian-style evidence combiner maintaining a normalized
// heuristic score over
// `Goal ∈ {benign, credentialHarvest, exfiltration, persistence,
// destructive, reconnaissance, lateralMovement}` per active process
// tree.
//
// Each independent evidence type updates the score via a stationary
// likelihood table shipped inside the binary (see `LikelihoodTable`
// below). The values are expert-authored, not fitted or calibrated against
// a representative outcome-labelled population. Consequently these values
// are advisory ranking scores, NOT real-world probabilities. The actor is
// intentionally small, deterministic, bounded, and locally explainable.

import Foundation

// MARK: - BayesianIntentEngine

public actor BayesianIntentEngine {

    // MARK: - Types

    public enum Goal: String, Sendable, CaseIterable, Codable {
        case benign
        case credentialHarvest
        case exfiltration
        case persistence
        case destructive
        case reconnaissance
        case lateralMovement
    }

    public enum Evidence: String, Sendable, CaseIterable {
        case credentialRead          // cred file open
        case registryEgress          // outbound to registry.npmjs.org / upload.pypi.org
        case nonRegistryEgress       // outbound to a webhook / non-CDN / GitHub repo API
        case launchAgentWrite        // persistence primitive
        case shellRcWrite            // ~/.zshrc / ~/.bashrc / agent-context dotfile
        case workflowWrite           // .github/workflows/*.yml
        case destructiveCmd          // rm -rf / dscl -delete
        case vmDetectionProbe        // sysctl / ioreg / system_profiler
        case localeProbe             // AppleLanguages read
        case obfuscatedContent       // PyArmor / _0x / single-line bundle
        case runtimeDrop             // bun / deno binary dropped
        case configFileTampered      // .npmrc / .pypirc modified by non-package-manager
    }

    /// Whether an `observe` call contributed independent evidence.
    ///
    /// Consumers that emit an alert from `observe` MUST require
    /// `addsIndependentEvidence == true`; a refresh or suppressed delivery
    /// returns the current snapshot for observability, but is not a new
    /// detection decision.
    public enum ObservationDisposition: String, Sendable, Codable, Equatable {
        case acceptedNewEvidence
        case acceptedRefresh
        case suppressedExactDuplicate
        case suppressedEvidenceCooldown
        case suppressedStaleReplay
        case suppressedOutsideEvidenceWindow
        case suppressedInvalidToken

        public var wasAccepted: Bool {
            switch self {
            case .acceptedNewEvidence, .acceptedRefresh:
                return true
            case .suppressedExactDuplicate,
                 .suppressedEvidenceCooldown,
                 .suppressedStaleReplay,
                 .suppressedOutsideEvidenceWindow,
                 .suppressedInvalidToken:
                return false
            }
        }

        public var addsIndependentEvidence: Bool {
            self == .acceptedNewEvidence
        }
    }

    /// Snapshot of the current normalized heuristic score per tree key.
    /// `probabilities` and `topProbability` retain their original names for
    /// source compatibility; they are not empirically calibrated probabilities.
    public struct Posterior: Sendable {
        public let treeKey: String              // process-lineage anchor
        public let probabilities: [Goal: Double]
        public let topGoal: Goal
        public let topProbability: Double
        public let evidenceLog: [Evidence]
        public let lastUpdate: Date
        /// v1.12.0 post-audit (H-Perf3): cached distinct-evidence-type
        /// count so the EventLoop alert-threshold check doesn't have to
        /// build `Set(posterior.evidenceLog)` per observe.
        public let distinctEvidenceCount: Int
        /// Non-nil only on a snapshot returned by `observe`.
        public let observationDisposition: ObservationDisposition?
        public var observationWasAccepted: Bool {
            observationDisposition?.wasAccepted == true
        }
        public var observationAddedIndependentEvidence: Bool {
            observationDisposition?.addsIndependentEvidence == true
        }

        public init(
            treeKey: String,
            probabilities: [Goal: Double],
            evidenceLog: [Evidence],
            lastUpdate: Date,
            observationDisposition: ObservationDisposition? = nil
        ) {
            self.treeKey = treeKey
            self.probabilities = probabilities
            let top = Goal.allCases
                .map { ($0, probabilities[$0] ?? 0) }
                .max {
                    if $0.1 == $1.1 { return $0.0.rawValue > $1.0.rawValue }
                    return $0.1 < $1.1
                } ?? (Goal.benign, 1.0)
            self.topGoal = top.0
            self.topProbability = top.1
            self.evidenceLog = evidenceLog
            self.lastUpdate = lastUpdate
            self.distinctEvidenceCount = Set(evidenceLog).count
            self.observationDisposition = observationDisposition
        }
    }

    /// Fixed-cardinality lifecycle and admission telemetry. The two
    /// conservation booleans are intended as health invariants.
    public struct Statistics: Sendable, Equatable {
        public let observations: UInt64
        public let acceptedNewEvidence: UInt64
        public let acceptedRefreshes: UInt64
        public let suppressedExactDuplicates: UInt64
        public let suppressedEvidenceCooldown: UInt64
        public let suppressedStaleReplays: UInt64
        public let suppressedOutsideEvidenceWindow: UInt64
        public let suppressedInvalidTokens: UInt64

        public let treesCreated: UInt64
        public let treesEvictedForCapacity: UInt64
        public let treesPrunedForIdle: UInt64
        public let treesReset: UInt64
        public let treesCleared: UInt64
        public let evidenceRecordsExpired: UInt64

        public let activeTrees: Int
        public let retainedEvidenceRecords: Int
        public let peakActiveTrees: Int
        public let maximumTrees: Int
        public let maximumEvidenceRecordsPerTree: Int

        public var acceptedObservations: UInt64 {
            acceptedNewEvidence + acceptedRefreshes
        }

        public var suppressedObservations: UInt64 {
            suppressedExactDuplicates
                + suppressedEvidenceCooldown
                + suppressedStaleReplays
                + suppressedOutsideEvidenceWindow
                + suppressedInvalidTokens
        }

        public var observationsConserved: Bool {
            observations == acceptedObservations + suppressedObservations
        }

        public var treeLifecycleConserved: Bool {
            treesCreated == UInt64(activeTrees)
                + treesEvictedForCapacity
                + treesPrunedForIdle
                + treesReset
                + treesCleared
        }

        public var treeCapacityRespected: Bool {
            activeTrees <= maximumTrees && peakActiveTrees <= maximumTrees
        }
    }

    public struct PruneResult: Sendable, Equatable {
        public let evidenceRecordsExpired: Int
        public let treesRemoved: Int
    }

    // MARK: - State

    /// At most one active contribution per evidence type is retained. A later
    /// independent observation refreshes that contribution rather than
    /// multiplying the same coarse signal repeatedly.
    private struct EvidenceRecord {
        let evidence: Evidence
        let observationToken: String?
        let observedAt: Date
    }

    private struct TreeState {
        var evidenceByType: [Evidence: EvidenceRecord]
        var latestObservationAt: Date
        var lastAcceptedAt: Date
    }

    private var trees: [String: TreeState] = [:]
    private let maxTrees: Int
    private let evidenceCooldown: TimeInterval
    private let evidenceWindow: TimeInterval
    private let decayHalfLife: TimeInterval
    private let treeIdleTTL: TimeInterval
    private let maxObservationTokenUTF8Bytes: Int
    private let likelihoodTable: LikelihoodTable

    private var observations: UInt64 = 0
    private var acceptedNewEvidence: UInt64 = 0
    private var acceptedRefreshes: UInt64 = 0
    private var suppressedExactDuplicates: UInt64 = 0
    private var suppressedEvidenceCooldown: UInt64 = 0
    private var suppressedStaleReplays: UInt64 = 0
    private var suppressedOutsideEvidenceWindow: UInt64 = 0
    private var suppressedInvalidTokens: UInt64 = 0
    private var treesCreated: UInt64 = 0
    private var treesEvictedForCapacity: UInt64 = 0
    private var treesPrunedForIdle: UInt64 = 0
    private var treesReset: UInt64 = 0
    private var treesCleared: UInt64 = 0
    private var evidenceRecordsExpired: UInt64 = 0
    private var peakActiveTrees: Int = 0

    /// Number of trees to evict in one pass when the dict exceeds
    /// `maxTrees`. Sized so the sort-and-drop cost amortizes across
    /// many subsequent observe calls before the cap is hit again.
    private static let evictionBatchSize: Int = 256

    // MARK: - Init

    public init(
        maxTrees: Int = 2048,
        evidenceCooldown: TimeInterval = 60,
        evidenceWindow: TimeInterval = 30 * 60,
        decayHalfLife: TimeInterval = 10 * 60,
        treeIdleTTL: TimeInterval = 60 * 60,
        maxObservationTokenUTF8Bytes: Int = 256
    ) {
        self.maxTrees = max(1, maxTrees)
        self.evidenceCooldown = max(0, evidenceCooldown)
        self.evidenceWindow = max(1, evidenceWindow)
        self.decayHalfLife = max(1, decayHalfLife)
        self.treeIdleTTL = max(max(1, evidenceWindow), treeIdleTTL)
        self.maxObservationTokenUTF8Bytes = max(1, maxObservationTokenUTF8Bytes)
        self.likelihoodTable = LikelihoodTable.default()
    }

    // MARK: - Public API

    /// Initial prior for a fresh process tree: heavily favors .benign
    /// (95%), small uniform allocation to malicious goals.
    private static let initialPrior: [Goal: Double] = {
        var p: [Goal: Double] = [:]
        let mal = Goal.allCases.filter { $0 != .benign }
        let malShare = 0.05 / Double(mal.count)
        p[.benign] = 0.95
        for g in mal { p[g] = malShare }
        return p
    }()

    /// Observe one piece of evidence on a process tree.
    ///
    /// `observationToken` should be the durable event identifier and
    /// `observedAt` its source timestamp. The pair (token, evidence type) is
    /// deduplicated, so one event may still contribute several DISTINCT
    /// evidence types. Calls without a token remain source-compatible and are
    /// protected by the per-type cooldown/refresh contract.
    /// `receivedAt` defaults to the processing clock and prevents a newly seen
    /// but already-expired replay from starting a fresh tree.
    ///
    /// Out-of-order observations inside the recent window are accepted when
    /// they add a different evidence type. Replays older than the retained
    /// contribution for the same type cannot replace newer evidence.
    @discardableResult
    public func observe(
        _ evidence: Evidence,
        treeKey: String,
        observationToken: String? = nil,
        observedAt: Date = Date(),
        receivedAt: Date = Date()
    ) -> Posterior {
        observations &+= 1

        guard (observationToken?.utf8.count ?? 0) <= maxObservationTokenUTF8Bytes else {
            suppressedInvalidTokens &+= 1
            return snapshot(
                treeKey: treeKey,
                state: trees[treeKey],
                asOf: trees[treeKey]?.latestObservationAt ?? max(observedAt, receivedAt),
                disposition: .suppressedInvalidToken
            )
        }

        if var state = trees[treeKey] {
            let referenceTime = max(state.latestObservationAt, observedAt, receivedAt)
            expireEvidence(in: &state, asOf: referenceTime)

            if referenceTime.timeIntervalSince(observedAt) > evidenceWindow {
                suppressedOutsideEvidenceWindow &+= 1
                state.latestObservationAt = referenceTime
                trees[treeKey] = state
                return snapshot(
                    treeKey: treeKey,
                    state: state,
                    asOf: referenceTime,
                    disposition: .suppressedOutsideEvidenceWindow
                )
            }
            state.latestObservationAt = referenceTime

            if let current = state.evidenceByType[evidence] {
                if let observationToken,
                   current.observationToken == observationToken {
                    suppressedExactDuplicates &+= 1
                    trees[treeKey] = state
                    return snapshot(
                        treeKey: treeKey,
                        state: state,
                        asOf: referenceTime,
                        disposition: .suppressedExactDuplicate
                    )
                }

                let interval = observedAt.timeIntervalSince(current.observedAt)
                if interval <= 0 {
                    suppressedStaleReplays &+= 1
                    trees[treeKey] = state
                    return snapshot(
                        treeKey: treeKey,
                        state: state,
                        asOf: referenceTime,
                        disposition: .suppressedStaleReplay
                    )
                }
                if interval < evidenceCooldown {
                    suppressedEvidenceCooldown &+= 1
                    trees[treeKey] = state
                    return snapshot(
                        treeKey: treeKey,
                        state: state,
                        asOf: referenceTime,
                        disposition: .suppressedEvidenceCooldown
                    )
                }

                state.evidenceByType[evidence] = EvidenceRecord(
                    evidence: evidence,
                    observationToken: observationToken,
                    observedAt: observedAt
                )
                state.lastAcceptedAt = max(state.lastAcceptedAt, referenceTime)
                acceptedRefreshes &+= 1
                trees[treeKey] = state
                return snapshot(
                    treeKey: treeKey,
                    state: state,
                    asOf: referenceTime,
                    disposition: .acceptedRefresh
                )
            }

            state.evidenceByType[evidence] = EvidenceRecord(
                evidence: evidence,
                observationToken: observationToken,
                observedAt: observedAt
            )
            state.lastAcceptedAt = max(state.lastAcceptedAt, referenceTime)
            acceptedNewEvidence &+= 1
            trees[treeKey] = state
            return snapshot(
                treeKey: treeKey,
                state: state,
                asOf: referenceTime,
                disposition: .acceptedNewEvidence
            )
        }

        let referenceTime = max(observedAt, receivedAt)
        if referenceTime.timeIntervalSince(observedAt) > evidenceWindow {
            suppressedOutsideEvidenceWindow &+= 1
            return snapshot(
                treeKey: treeKey,
                state: nil,
                asOf: referenceTime,
                disposition: .suppressedOutsideEvidenceWindow
            )
        }

        makeRoomForNewTree()
        let record = EvidenceRecord(
            evidence: evidence,
            observationToken: observationToken,
            observedAt: observedAt
        )
        let state = TreeState(
            evidenceByType: [evidence: record],
            latestObservationAt: referenceTime,
            lastAcceptedAt: referenceTime
        )
        trees[treeKey] = state
        treesCreated &+= 1
        acceptedNewEvidence &+= 1
        peakActiveTrees = max(peakActiveTrees, trees.count)
        return snapshot(
            treeKey: treeKey,
            state: state,
            asOf: referenceTime,
            disposition: .acceptedNewEvidence
        )
    }

    /// Returns a decayed snapshot. Advancing `asOf` also expires evidence
    /// outside the recent window, but does not keep the tree alive.
    public func posterior(treeKey: String, asOf: Date = Date()) -> Posterior? {
        guard var state = trees[treeKey] else { return nil }
        let referenceTime = max(state.latestObservationAt, asOf)
        expireEvidence(in: &state, asOf: referenceTime)
        state.latestObservationAt = referenceTime
        trees[treeKey] = state
        return snapshot(treeKey: treeKey, state: state, asOf: referenceTime)
    }

    public func reset(treeKey: String) {
        if trees.removeValue(forKey: treeKey) != nil {
            treesReset &+= 1
        }
    }

    public func clearAll() {
        treesCleared &+= UInt64(trees.count)
        trees.removeAll()
    }

    /// Explicit lifecycle seam for callers that know a process/session ended.
    public func endSession(treeKey: String) {
        reset(treeKey: treeKey)
    }

    /// Prunes expired evidence and removes idle trees. Suppressed/replayed
    /// callbacks never refresh the idle deadline.
    @discardableResult
    public func prune(asOf: Date = Date()) -> PruneResult {
        let expiredBefore = evidenceRecordsExpired
        var removedTrees = 0
        for treeKey in trees.keys.sorted() {
            guard var state = trees[treeKey] else { continue }
            let referenceTime = max(state.latestObservationAt, asOf)
            expireEvidence(in: &state, asOf: referenceTime)
            if asOf.timeIntervalSince(state.lastAcceptedAt) > treeIdleTTL {
                trees.removeValue(forKey: treeKey)
                treesPrunedForIdle &+= 1
                removedTrees += 1
            } else {
                state.latestObservationAt = referenceTime
                trees[treeKey] = state
            }
        }
        return PruneResult(
            evidenceRecordsExpired: Int(evidenceRecordsExpired - expiredBefore),
            treesRemoved: removedTrees
        )
    }

    public func trackedTreeCount() -> Int { trees.count }

    public func statistics() -> Statistics {
        Statistics(
            observations: observations,
            acceptedNewEvidence: acceptedNewEvidence,
            acceptedRefreshes: acceptedRefreshes,
            suppressedExactDuplicates: suppressedExactDuplicates,
            suppressedEvidenceCooldown: suppressedEvidenceCooldown,
            suppressedStaleReplays: suppressedStaleReplays,
            suppressedOutsideEvidenceWindow: suppressedOutsideEvidenceWindow,
            suppressedInvalidTokens: suppressedInvalidTokens,
            treesCreated: treesCreated,
            treesEvictedForCapacity: treesEvictedForCapacity,
            treesPrunedForIdle: treesPrunedForIdle,
            treesReset: treesReset,
            treesCleared: treesCleared,
            evidenceRecordsExpired: evidenceRecordsExpired,
            activeTrees: trees.count,
            retainedEvidenceRecords: trees.values.reduce(0) { $0 + $1.evidenceByType.count },
            peakActiveTrees: peakActiveTrees,
            maximumTrees: maxTrees,
            maximumEvidenceRecordsPerTree: Evidence.allCases.count
        )
    }

    // MARK: - Bounded-state helpers

    private func makeRoomForNewTree() {
        guard trees.count >= maxTrees else { return }
        let amortization = max(1, min(Self.evictionBatchSize, maxTrees / 4))
        let evictionCount = min(trees.count, amortization)
        let oldestKeys = trees
            .sorted {
                if $0.value.lastAcceptedAt == $1.value.lastAcceptedAt {
                    return $0.key < $1.key
                }
                return $0.value.lastAcceptedAt < $1.value.lastAcceptedAt
            }
            .prefix(evictionCount)
            .map(\.key)
        for key in oldestKeys {
            if trees.removeValue(forKey: key) != nil {
                treesEvictedForCapacity &+= 1
            }
        }
    }

    private func expireEvidence(in state: inout TreeState, asOf: Date) {
        let expired = state.evidenceByType.filter {
            asOf.timeIntervalSince($0.value.observedAt) > evidenceWindow
        }.map(\.key)
        guard !expired.isEmpty else { return }
        for evidence in expired {
            state.evidenceByType.removeValue(forKey: evidence)
        }
        evidenceRecordsExpired &+= UInt64(expired.count)
    }

    private func snapshot(
        treeKey: String,
        state: TreeState?,
        asOf: Date,
        disposition: ObservationDisposition? = nil
    ) -> Posterior {
        guard let state else {
            return Posterior(
                treeKey: treeKey,
                probabilities: Self.initialPrior,
                evidenceLog: [],
                lastUpdate: asOf,
                observationDisposition: disposition
            )
        }

        let orderedRecords = state.evidenceByType.values.sorted {
            if $0.observedAt == $1.observedAt {
                return $0.evidence.rawValue < $1.evidence.rawValue
            }
            return $0.observedAt < $1.observedAt
        }
        return Posterior(
            treeKey: treeKey,
            probabilities: normalizedScores(records: orderedRecords, asOf: asOf),
            evidenceLog: orderedRecords.map(\.evidence),
            lastUpdate: state.lastAcceptedAt,
            observationDisposition: disposition
        )
    }

    /// Temper each likelihood contribution by exponential age decay. In log
    /// space, a contribution's exponent approaches zero as it ages, returning
    /// the normalized score smoothly toward the initial prior.
    private func normalizedScores(records: [EvidenceRecord], asOf: Date) -> [Goal: Double] {
        var logScores: [Goal: Double] = [:]
        for goal in Goal.allCases {
            var score = log(max(Self.initialPrior[goal] ?? 0, Double.leastNonzeroMagnitude))
            for record in records {
                let age = max(0, asOf.timeIntervalSince(record.observedAt))
                let weight = pow(0.5, age / decayHalfLife)
                let likelihood = likelihoodTable.likelihoods(for: record.evidence)[goal] ?? 1
                score += weight * log(max(likelihood, Double.leastNonzeroMagnitude))
            }
            logScores[goal] = score
        }

        let maximumLogScore = logScores.values.max() ?? 0
        var unnormalized: [Goal: Double] = [:]
        for goal in Goal.allCases {
            unnormalized[goal] = exp((logScores[goal] ?? maximumLogScore) - maximumLogScore)
        }
        // Dictionary iteration order is intentionally unspecified and each
        // allocation can use a different seed. Summing in Goal order keeps an
        // unchanged snapshot bit-stable across exact duplicate callbacks.
        let total = Goal.allCases.reduce(0.0) { partial, goal in
            partial + (unnormalized[goal] ?? 0)
        }
        guard total.isFinite, total > 0 else { return Self.initialPrior }
        return unnormalized.mapValues { $0 / total }
    }
}

// MARK: - LikelihoodTable

/// Stationary expert-authored compatibility table shipped inside the binary.
/// These weights rank how consistent an evidence type is with each goal. They
/// have not been calibrated as P(E|G) against a representative labelled set.
struct LikelihoodTable: Sendable {
    /// Values are unnormalised heuristic likelihood weights. Only their ratio
    /// across goals for a given evidence type is used.
    let table: [BayesianIntentEngine.Evidence: [BayesianIntentEngine.Goal: Double]]

    func likelihoods(for evidence: BayesianIntentEngine.Evidence) -> [BayesianIntentEngine.Goal: Double] {
        table[evidence] ?? [:]
    }

    static func `default`() -> LikelihoodTable {
        typealias E = BayesianIntentEngine.Evidence
        typealias G = BayesianIntentEngine.Goal
        // Higher means "this evidence is more consistent with goal G".
        // Threshold behavior is pinned by regression tests; these weights do
        // not carry an empirical calibration claim.
        let t: [E: [G: Double]] = [
            .credentialRead: [
                .benign: 0.02, .credentialHarvest: 0.9, .exfiltration: 0.4,
                .persistence: 0.05, .destructive: 0.05, .reconnaissance: 0.1,
                .lateralMovement: 0.5,
            ],
            .registryEgress: [
                .benign: 0.6, .credentialHarvest: 0.05, .exfiltration: 0.1,
                .persistence: 0.05, .destructive: 0.05, .reconnaissance: 0.05,
                .lateralMovement: 0.6,
            ],
            .nonRegistryEgress: [
                .benign: 0.05, .credentialHarvest: 0.3, .exfiltration: 0.9,
                .persistence: 0.1, .destructive: 0.05, .reconnaissance: 0.1,
                .lateralMovement: 0.3,
            ],
            .launchAgentWrite: [
                .benign: 0.05, .credentialHarvest: 0.05, .exfiltration: 0.05,
                .persistence: 0.95, .destructive: 0.05, .reconnaissance: 0.02,
                .lateralMovement: 0.05,
            ],
            .shellRcWrite: [
                .benign: 0.05, .credentialHarvest: 0.05, .exfiltration: 0.05,
                .persistence: 0.85, .destructive: 0.05, .reconnaissance: 0.02,
                .lateralMovement: 0.05,
            ],
            .workflowWrite: [
                .benign: 0.05, .credentialHarvest: 0.05, .exfiltration: 0.1,
                .persistence: 0.6, .destructive: 0.05, .reconnaissance: 0.02,
                .lateralMovement: 0.3,
            ],
            .destructiveCmd: [
                .benign: 0.01, .credentialHarvest: 0.05, .exfiltration: 0.05,
                .persistence: 0.05, .destructive: 0.95, .reconnaissance: 0.02,
                .lateralMovement: 0.05,
            ],
            .vmDetectionProbe: [
                .benign: 0.05, .credentialHarvest: 0.15, .exfiltration: 0.2,
                .persistence: 0.1, .destructive: 0.05, .reconnaissance: 0.85,
                .lateralMovement: 0.1,
            ],
            .localeProbe: [
                .benign: 0.05, .credentialHarvest: 0.15, .exfiltration: 0.2,
                .persistence: 0.1, .destructive: 0.1, .reconnaissance: 0.85,
                .lateralMovement: 0.1,
            ],
            .obfuscatedContent: [
                .benign: 0.05, .credentialHarvest: 0.3, .exfiltration: 0.4,
                .persistence: 0.4, .destructive: 0.3, .reconnaissance: 0.2,
                .lateralMovement: 0.5,
            ],
            .runtimeDrop: [
                .benign: 0.02, .credentialHarvest: 0.3, .exfiltration: 0.5,
                .persistence: 0.2, .destructive: 0.2, .reconnaissance: 0.05,
                .lateralMovement: 0.6,
            ],
            .configFileTampered: [
                .benign: 0.02, .credentialHarvest: 0.4, .exfiltration: 0.2,
                .persistence: 0.3, .destructive: 0.05, .reconnaissance: 0.1,
                .lateralMovement: 0.9,
            ],
        ]
        return LikelihoodTable(table: t)
    }
}
