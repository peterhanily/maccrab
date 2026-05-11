// EdgeRelation.swift
// MacCrabCore
//
// v1.10 TraceGraph (PR-7) — the 13-relation vocabulary from §9 of the
// v1.10.0 spec. Kept intentionally small so the bundle format and
// graph-rule schema commit to a stable surface without churn.

import Foundation

public enum EdgeRelation: String, Sendable, Codable, CaseIterable, Equatable {
    case spawned               = "spawned"
    case read                  = "read"
    case wrote                 = "wrote"
    case renamed               = "renamed"
    case deleted               = "deleted"
    case connectedTo           = "connected_to"
    case createdPersistence    = "created_persistence"
    case loadedCode            = "loaded_code"
    case signedBy              = "signed_by"
    case associatedWithAgent   = "associated_with_agent"
    case triggeredRule         = "triggered_rule"
    case matchedSequence       = "matched_sequence"
    case caused                = "caused"

    /// Default minimum confidence tier per §23.2 — used by the graph
    /// rule evaluator when a rule omits an explicit `min_tier`. Encoded
    /// here so PR-13's evaluator and PR-7's edge builder share one
    /// source of truth.
    public var defaultMinimumTier: ConfidenceTier {
        switch self {
        case .associatedWithAgent: return .strongInferred
        case .createdPersistence:  return .strongInferred
        case .caused:              return .strongInferred
        case .spawned:             return .weakInferred
        case .read:                return .weakInferred
        case .wrote:               return .weakInferred
        case .renamed:             return .weakInferred
        case .deleted:             return .weakInferred
        case .connectedTo:         return .weakInferred
        case .loadedCode:          return .weakInferred
        case .signedBy:            return .weakInferred
        case .triggeredRule:       return .weakInferred
        case .matchedSequence:     return .weakInferred
        }
    }
}
