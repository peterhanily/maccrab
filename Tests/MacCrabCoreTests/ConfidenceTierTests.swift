// ConfidenceTierTests.swift
// v1.10 TraceGraph (PR-7) — tests for ConfidenceTier scoring and
// EdgeRelation default-min-tier table.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("TraceGraph: ConfidenceTier scoring")
struct ConfidenceTierTests {

    @Test("Score → tier mapping per §11.1")
    func scoreToTier() {
        #expect(ConfidenceTier(score: 1.00) == .direct)
        #expect(ConfidenceTier(score: 0.95) == .direct)
        #expect(ConfidenceTier(score: 0.90) == .direct)
        #expect(ConfidenceTier(score: 0.89) == .strongInferred)
        #expect(ConfidenceTier(score: 0.80) == .strongInferred)
        #expect(ConfidenceTier(score: 0.70) == .strongInferred)
        #expect(ConfidenceTier(score: 0.69) == .weakInferred)
        #expect(ConfidenceTier(score: 0.50) == .weakInferred)
        #expect(ConfidenceTier(score: 0.30) == .weakInferred)
        #expect(ConfidenceTier(score: 0.29) == .temporalOnly)
        #expect(ConfidenceTier(score: 0.10) == .temporalOnly)
        #expect(ConfidenceTier(score: 0.00) == .temporalOnly)
    }

    @Test("temporalOnly is not causal — §11.2 invariant")
    func temporalOnlyExcluded() {
        #expect(!ConfidenceTier.temporalOnly.isCausal)
        #expect(ConfidenceTier.weakInferred.isCausal)
        #expect(ConfidenceTier.strongInferred.isCausal)
        #expect(ConfidenceTier.direct.isCausal)
    }

    @Test("Tier ordering by rank")
    func tierOrdering() {
        #expect(ConfidenceTier.direct.rank > ConfidenceTier.strongInferred.rank)
        #expect(ConfidenceTier.strongInferred.rank > ConfidenceTier.weakInferred.rank)
        #expect(ConfidenceTier.weakInferred.rank > ConfidenceTier.temporalOnly.rank)
    }

    @Test("meets() is true when self at-or-above other")
    func meetsThreshold() {
        #expect(ConfidenceTier.direct.meets(.weakInferred))
        #expect(ConfidenceTier.direct.meets(.direct))
        #expect(ConfidenceTier.strongInferred.meets(.weakInferred))
        #expect(!ConfidenceTier.weakInferred.meets(.strongInferred))
        #expect(!ConfidenceTier.temporalOnly.meets(.weakInferred))
    }
}

@Suite("TraceGraph: EdgeRelation default min-tier table")
struct EdgeRelationDefaultsTests {

    @Test("§23.2: associated_with_agent defaults to strong_inferred")
    func aiAttribution() {
        #expect(EdgeRelation.associatedWithAgent.defaultMinimumTier == .strongInferred)
    }

    @Test("§23.2: created_persistence defaults to strong_inferred")
    func persistence() {
        #expect(EdgeRelation.createdPersistence.defaultMinimumTier == .strongInferred)
    }

    @Test("§23.2: spawned defaults to weak_inferred")
    func spawned() {
        #expect(EdgeRelation.spawned.defaultMinimumTier == .weakInferred)
    }

    @Test("Every relation has a non-temporalOnly default")
    func noTemporalOnlyDefaults() {
        // §23.2: temporal_only never satisfies graph rules unless
        // explicitly opted-in — so no relation may default to it.
        for relation in EdgeRelation.allCases {
            #expect(relation.defaultMinimumTier != .temporalOnly,
                    "Relation \(relation.rawValue) defaults to temporalOnly — violates §23.2")
        }
    }
}
