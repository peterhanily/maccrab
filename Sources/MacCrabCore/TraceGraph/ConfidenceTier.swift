// ConfidenceTier.swift
// MacCrabCore
//
// v1.10 TraceGraph (PR-7) — categorical confidence tier per §11.1 of
// the v1.10.0 spec. Every TraceEdge carries both a numeric confidence
// (for tuning, scoring, future ML) and a categorical tier (for the UI
// and explainer).
//
// The hard rule from §11.2: pure time proximity must NEVER produce a
// strong causal edge. `temporal_only` edges exist for the rolling
// graph but are excluded from the core trace layer (§14.4 weights
// table) and never satisfy graph rules unless explicitly opted into
// via a separate `temporal_correlation` operator (§23.2).

import Foundation

public enum ConfidenceTier: String, Sendable, Codable, CaseIterable, Equatable {
    case direct           = "direct"             // 0.90 – 1.00
    case strongInferred   = "strong_inferred"    // 0.70 – 0.89
    case weakInferred     = "weak_inferred"      // 0.30 – 0.69
    case temporalOnly     = "temporal_only"      // < 0.30 (never causal)

    /// Map a numeric confidence to the canonical tier per §11.1.
    public init(score: Double) {
        switch score {
        case 0.90 ... 1.00: self = .direct
        case 0.70 ..< 0.90: self = .strongInferred
        case 0.30 ..< 0.70: self = .weakInferred
        default:            self = .temporalOnly
        }
    }

    /// Returns true iff this tier is permitted on the core trace
    /// critical path (§14.4 explicit "Excluded from core" entry).
    public var isCausal: Bool {
        self != .temporalOnly
    }

    /// Tier comparison — useful for graph-rule `min_tier` enforcement
    /// (§23.2). Higher == more confident.
    public var rank: Int {
        switch self {
        case .temporalOnly:   return 0
        case .weakInferred:   return 1
        case .strongInferred: return 2
        case .direct:         return 3
        }
    }

    /// True when `self` is at least as strong as `other`.
    public func meets(_ other: ConfidenceTier) -> Bool {
        rank >= other.rank
    }
}
