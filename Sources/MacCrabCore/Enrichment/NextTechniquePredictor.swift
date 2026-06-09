// NextTechniquePredictor.swift
// MacCrabCore
//
// Lightweight kill-chain-graph predictor. Given a sequence of MITRE
// ATT&CK tactics observed for a process tree, returns the top-N most-
// likely next tactics from a stationary transition prior shipped
// inside the binary.
//
// Inspired by KillChainGraph (arXiv 2508.18230, Sept 2025) but with a
// hand-calibrated 14x14 transition matrix instead of a trained
// ensemble — no GPU, no online learning, fully reproducible.
//
// Also bundles CounterfactualReasoner: given a fired sequence rule,
// walks back to identify the earliest step where the available
// prevention capability (DNS sinkhole, NetworkBlocker, PersistenceGuard)
// could have aborted the chain. Surfaces "blocking X at T-Ns would
// have stopped this" copy for the dashboard.

import Foundation
import os.log

// MARK: - NextTechniquePredictor

public actor NextTechniquePredictor {

    private let logger = Logger(subsystem: "com.maccrab.enrichment", category: "next-technique")

    /// MITRE ATT&CK tactics (Enterprise, post-2024 set).
    public enum Tactic: String, Sendable, CaseIterable, Codable {
        case reconnaissance      = "TA0043"
        case resourceDevelopment = "TA0042"
        case initialAccess       = "TA0001"
        case execution           = "TA0002"
        case persistence         = "TA0003"
        case privilegeEscalation = "TA0004"
        case defenseEvasion      = "TA0005"
        case credentialAccess    = "TA0006"
        case discovery           = "TA0007"
        case lateralMovement     = "TA0008"
        case collection          = "TA0009"
        case commandAndControl   = "TA0011"
        case exfiltration        = "TA0010"
        case impact              = "TA0040"
    }

    public struct Prediction: Sendable {
        public let tactic: Tactic
        public let probability: Double
        public init(tactic: Tactic, probability: Double) {
            self.tactic = tactic
            self.probability = probability
        }
    }

    /// `transition[from][to] = P(to | from)`, row-normalised.
    private let transition: [Tactic: [Tactic: Double]]

    public init() {
        self.transition = Self.makeTransitionMatrix()
    }

    /// Predict the top-N most-likely next tactics given a prefix. Uses
    /// only the most-recent tactic for v1.12.0 (Markov-1). Longer
    /// context is left for v1.13.x once we have a deployment-ready
    /// training corpus.
    public func predictNext(after prefix: [Tactic], topN: Int = 3) -> [Prediction] {
        guard let lastTactic = prefix.last else {
            return [Prediction(tactic: .initialAccess, probability: 0.4)]
        }
        let row = transition[lastTactic] ?? [:]
        let sorted = row
            .map { Prediction(tactic: $0.key, probability: $0.value) }
            .sorted { $0.probability > $1.probability }
        return Array(sorted.prefix(topN))
    }

    /// Calibrated from the 41 existing sequence rules + the published
    /// 2024-2026 supply-chain incident corpus. Each "from" row is
    /// normalised so the probabilities sum to ≤1 (the remainder
    /// represents "end of chain").
    nonisolated static func makeTransitionMatrix() -> [Tactic: [Tactic: Double]] {
        typealias T = Tactic
        var m: [T: [T: Double]] = [:]
        m[.reconnaissance] = [
            .initialAccess: 0.55, .discovery: 0.15, .credentialAccess: 0.05,
            .resourceDevelopment: 0.05, .execution: 0.10,
        ]
        m[.resourceDevelopment] = [
            .initialAccess: 0.6, .execution: 0.1, .commandAndControl: 0.1,
            .credentialAccess: 0.05,
        ]
        m[.initialAccess] = [
            .execution: 0.6, .persistence: 0.1, .credentialAccess: 0.15,
            .discovery: 0.05,
        ]
        m[.execution] = [
            .persistence: 0.25, .credentialAccess: 0.25, .defenseEvasion: 0.15,
            .commandAndControl: 0.15, .discovery: 0.1, .privilegeEscalation: 0.05,
        ]
        m[.persistence] = [
            .defenseEvasion: 0.15, .credentialAccess: 0.2, .commandAndControl: 0.2,
            .discovery: 0.15, .lateralMovement: 0.05, .exfiltration: 0.1,
        ]
        m[.privilegeEscalation] = [
            .defenseEvasion: 0.3, .credentialAccess: 0.25, .persistence: 0.15,
            .discovery: 0.1,
        ]
        m[.defenseEvasion] = [
            .credentialAccess: 0.2, .commandAndControl: 0.2, .persistence: 0.15,
            .discovery: 0.1, .impact: 0.1, .exfiltration: 0.1,
        ]
        m[.credentialAccess] = [
            .lateralMovement: 0.3, .exfiltration: 0.35, .discovery: 0.1,
            .commandAndControl: 0.15, .collection: 0.05,
        ]
        m[.discovery] = [
            .credentialAccess: 0.25, .lateralMovement: 0.15, .collection: 0.15,
            .defenseEvasion: 0.1, .commandAndControl: 0.1,
        ]
        m[.lateralMovement] = [
            .credentialAccess: 0.2, .persistence: 0.2, .collection: 0.15,
            .commandAndControl: 0.15, .exfiltration: 0.2,
        ]
        m[.collection] = [
            .exfiltration: 0.6, .commandAndControl: 0.2,
        ]
        m[.commandAndControl] = [
            .exfiltration: 0.4, .impact: 0.15, .lateralMovement: 0.15,
            .credentialAccess: 0.1, .persistence: 0.05,
        ]
        m[.exfiltration] = [
            .impact: 0.25, .lateralMovement: 0.15, .commandAndControl: 0.1,
        ]
        m[.impact] = [:]  // Terminal — most chains end here.
        return m
    }
}

// MARK: - CounterfactualReasoner

public actor CounterfactualReasoner {

    private let logger = Logger(subsystem: "com.maccrab.enrichment", category: "counterfactual")

    /// Prevention capabilities MacCrab can chokepoint at.
    public enum PreventionCapability: String, Sendable, CaseIterable {
        case dnsSinkhole          // DNSSinkhole — block an outbound DNS
        case networkBlocker       // NetworkBlocker — kill an outbound TCP
        case persistenceGuard     // PersistenceGuard — block a LaunchAgent write
        case supplyChainGate      // SupplyChainGate — kill a fresh-pkg install
        case manualResponse       // analyst-driven (panic button, TCC revocation)
    }

    public struct ChainStep: Sendable {
        public let stepId: String         // sequence rule step id
        public let tactic: NextTechniquePredictor.Tactic
        public let timestamp: Date
        public let primitive: String      // "outbound TCP", "LaunchAgent write", etc.
        public init(stepId: String, tactic: NextTechniquePredictor.Tactic, timestamp: Date, primitive: String) {
            self.stepId = stepId
            self.tactic = tactic
            self.timestamp = timestamp
            self.primitive = primitive
        }
    }

    public struct CounterfactualResult: Sendable {
        /// The earliest step at which any prevention capability could
        /// have aborted the chain. Nil if no capability matches.
        public let earliestBlockable: ChainStep?
        public let blockingCapability: PreventionCapability?
        public let secondsBeforeImpact: Int?
        public let narrative: String

        public init(earliestBlockable: ChainStep?, blockingCapability: PreventionCapability?, secondsBeforeImpact: Int?, narrative: String) {
            self.earliestBlockable = earliestBlockable
            self.blockingCapability = blockingCapability
            self.secondsBeforeImpact = secondsBeforeImpact
            self.narrative = narrative
        }
    }

    public init() {}

    /// Analyze a fired chain. Walks each step in chronological order
    /// and returns the first one whose primitive matches an available
    /// capability. The narrative is dashboard-ready ("Blocking the
    /// outbound TCP at T-42s would have aborted this chain").
    public func analyze(chain: [ChainStep]) -> CounterfactualResult {
        guard let last = chain.last, let first = chain.first else {
            return CounterfactualResult(
                earliestBlockable: nil, blockingCapability: nil,
                secondsBeforeImpact: nil,
                narrative: "no chain steps available for counterfactual analysis"
            )
        }
        let sorted = chain.sorted { $0.timestamp < $1.timestamp }
        for step in sorted {
            if let cap = Self.capability(for: step.primitive) {
                let delta = Int(last.timestamp.timeIntervalSince(step.timestamp))
                let narrative = "Blocking the \(step.primitive) at step '\(step.stepId)' (T-\(delta)s before impact) via \(cap.rawValue) would have aborted this chain."
                return CounterfactualResult(
                    earliestBlockable: step,
                    blockingCapability: cap,
                    secondsBeforeImpact: delta,
                    narrative: narrative
                )
            }
        }
        let span = Int(last.timestamp.timeIntervalSince(first.timestamp))
        return CounterfactualResult(
            earliestBlockable: nil, blockingCapability: nil,
            secondsBeforeImpact: span,
            narrative: "chain completed in \(span)s — no shipped prevention capability matched any observed step primitive"
        )
    }

    /// Map an observed step primitive to the capability that could
    /// have prevented it. Update as new prevention actors land.
    nonisolated static func capability(for primitive: String) -> PreventionCapability? {
        let p = primitive.lowercased()
        if p.contains("dns") { return .dnsSinkhole }
        if p.contains("outbound") || p.contains("tcp") || p.contains("network") { return .networkBlocker }
        if p.contains("launchagent") || p.contains("launchdaemon") || p.contains("plist") { return .persistenceGuard }
        if p.contains("npm install") || p.contains("pip install") || p.contains("fresh package") { return .supplyChainGate }
        return nil
    }
}
