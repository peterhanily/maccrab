// BayesianIntentEngine.swift
// MacCrabCore
//
// Lightweight Bayesian belief network maintaining a posterior over
// `Goal ∈ {benign, credentialHarvest, exfiltration, persistence,
// destructive, reconnaissance, lateralMovement}` per active process
// tree.
//
// Each observed evidence type updates the posterior via a stationary
// likelihood table shipped inside the binary (see `LikelihoodTable`
// below). The math is intentionally minimal — no online learning, no
// neural net — so the actor is cheap, reproducible, and explainable
// to a security analyst staring at the dashboard.
//
// Why this is novel for an EDR: most products show "rule X fired";
// Vectra surfaces an intent label; **nobody on macOS currently shows
// a real-time posterior probability across attacker goals as the kill
// chain develops**. The KillChainGraph paper (arXiv 2508.18230) does
// something similar with a transformer but requires GPU. This actor
// runs on a phone-grade CPU.

import Foundation
import os.log

// MARK: - BayesianIntentEngine

public actor BayesianIntentEngine {

    private let logger = Logger(subsystem: "com.maccrab.enrichment", category: "bayesian-intent")

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

    /// Snapshot of the current posterior per tree key.
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

        public init(treeKey: String, probabilities: [Goal: Double], evidenceLog: [Evidence], lastUpdate: Date) {
            self.treeKey = treeKey
            self.probabilities = probabilities
            let top = probabilities.max(by: { $0.value < $1.value }) ?? (Goal.benign, 1.0)
            self.topGoal = top.key
            self.topProbability = top.value
            self.evidenceLog = evidenceLog
            self.lastUpdate = lastUpdate
            self.distinctEvidenceCount = Set(evidenceLog).count
        }
    }

    // MARK: - State

    /// Per-tree state.
    private struct TreeState {
        var probabilities: [Goal: Double]
        var evidenceLog: [Evidence]
        var lastUpdate: Date
    }

    private var trees: [String: TreeState] = [:]
    private let maxTrees: Int
    private let likelihoodTable: LikelihoodTable

    /// Number of trees to evict in one pass when the dict exceeds
    /// `maxTrees`. Sized so the sort-and-drop cost amortizes across
    /// many subsequent observe calls before the cap is hit again.
    private static let evictionBatchSize: Int = 256

    // MARK: - Init

    public init(maxTrees: Int = 2048) {
        self.maxTrees = maxTrees
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

    /// Observe one piece of evidence on a process tree. Updates the
    /// posterior in O(|Goal|) and evicts the oldest tree if we're over
    /// capacity. Returns the new posterior.
    @discardableResult
    public func observe(_ evidence: Evidence, treeKey: String) -> Posterior {
        var state = trees[treeKey] ?? TreeState(
            probabilities: Self.initialPrior,
            evidenceLog: [],
            lastUpdate: Date()
        )

        // Bayesian update: posterior(G) ∝ prior(G) * likelihood(E|G).
        let likelihoods = likelihoodTable.likelihoods(for: evidence)
        var unnormalized: [Goal: Double] = [:]
        for g in Goal.allCases {
            let prior = state.probabilities[g] ?? 0
            let lik = likelihoods[g] ?? 1.0
            unnormalized[g] = prior * lik
        }
        let total = unnormalized.values.reduce(0, +)
        if total > 0 {
            for (g, v) in unnormalized {
                state.probabilities[g] = v / total
            }
        }
        state.evidenceLog.append(evidence)
        if state.evidenceLog.count > 64 {
            state.evidenceLog.removeFirst(state.evidenceLog.count - 64)
        }
        state.lastUpdate = Date()
        trees[treeKey] = state

        // v1.12.0 post-audit (H-Perf2): the prior `trees.min(by:)` was
        // O(N) per observe once the dict crossed maxTrees. On a fork-
        // bomb / large `npm install` burst that creates many short-
        // lived process trees, every event would pay the full-dict
        // scan. Switch to batch eviction: when over cap, drop the
        // oldest `evictionBatchSize` trees in one pass so the cost
        // amortizes to ~O(1) per observe.
        // Batch size is clamped so tests with small maxTrees (e.g. 3)
        // don't try to evict more entries than exist past the cap +
        // batch headroom.
        if trees.count > maxTrees {
            let overage = trees.count - maxTrees
            // Drop `overage + min(batchSize, maxTrees / 4)` so we stay
            // under cap with a margin proportional to capacity. For
            // tiny test caps this collapses to dropping just the
            // overage; for production (maxTrees=2048) it amortizes by
            // dropping ~256 at a time.
            let amortization = max(1, min(Self.evictionBatchSize, maxTrees / 4))
            let toEvict = overage + amortization - 1
            let oldestKeys = trees
                .sorted { $0.value.lastUpdate < $1.value.lastUpdate }
                .prefix(toEvict)
                .map { $0.key }
            for key in oldestKeys {
                trees.removeValue(forKey: key)
            }
        }

        return Posterior(
            treeKey: treeKey,
            probabilities: state.probabilities,
            evidenceLog: state.evidenceLog,
            lastUpdate: state.lastUpdate
        )
    }

    public func posterior(treeKey: String) -> Posterior? {
        guard let state = trees[treeKey] else { return nil }
        return Posterior(
            treeKey: treeKey,
            probabilities: state.probabilities,
            evidenceLog: state.evidenceLog,
            lastUpdate: state.lastUpdate
        )
    }

    public func reset(treeKey: String) {
        trees.removeValue(forKey: treeKey)
    }

    public func clearAll() {
        trees.removeAll()
    }

    public func trackedTreeCount() -> Int { trees.count }
}

// MARK: - LikelihoodTable

/// Stationary P(E|G) table shipped inside the binary. Values are
/// hand-calibrated from published 2024-2026 incident corpora; they
/// represent "how surprising is this evidence given goal G".
struct LikelihoodTable: Sendable {
    /// `table[Evidence][Goal] = P(E | G)`. Values are unnormalised
    /// likelihoods — what matters is the *ratio* across goals for a
    /// given evidence.
    let table: [BayesianIntentEngine.Evidence: [BayesianIntentEngine.Goal: Double]]

    func likelihoods(for evidence: BayesianIntentEngine.Evidence) -> [BayesianIntentEngine.Goal: Double] {
        table[evidence] ?? [:]
    }

    static func `default`() -> LikelihoodTable {
        typealias E = BayesianIntentEngine.Evidence
        typealias G = BayesianIntentEngine.Goal
        // Likelihoods: higher = "this evidence is more consistent with
        // goal G". Tuned so that 3-4 strong pieces of evidence in the
        // same direction push the posterior > 0.7 in that goal.
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
