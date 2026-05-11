// CriticalPathScorerTests.swift
// v1.10 TraceGraph (PR-8) — tests for CriticalPathScorer §14.4.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("TraceGraph: CriticalPathScorer")
struct CriticalPathScorerTests {

    private let now = Date(timeIntervalSince1970: 1_700_000_000)

    private func makeEdge(
        from: String,
        to: String,
        relation: EdgeRelation,
        confidence: Double
    ) -> TraceEdge {
        EdgeBuilder.build(
            sourceEntityId: from,
            targetEntityId: to,
            relation: relation,
            confidence: confidence,
            observedAt: now
        )
    }

    @Test("Temporal-only edges score zero")
    func temporalOnlyZero() {
        let edge = makeEdge(from: "a", to: "b", relation: .read, confidence: 0.1)
        #expect(CriticalPathScorer.score(edge: edge) == 0.0)
    }

    @Test("Higher relation weight beats lower at same confidence")
    func relationWeightsOrdered() {
        let persist = makeEdge(from: "a", to: "b", relation: .createdPersistence, confidence: 0.95)
        let agent = makeEdge(from: "a", to: "b", relation: .associatedWithAgent, confidence: 0.95)
        let spawn = makeEdge(from: "a", to: "b", relation: .spawned, confidence: 0.95)
        let wrote = makeEdge(from: "a", to: "b", relation: .wrote, confidence: 0.95)

        #expect(CriticalPathScorer.score(edge: persist) > CriticalPathScorer.score(edge: spawn))
        #expect(CriticalPathScorer.score(edge: agent) > CriticalPathScorer.score(edge: spawn))
        #expect(CriticalPathScorer.score(edge: spawn) > CriticalPathScorer.score(edge: wrote))
    }

    @Test("Trust-boundary bonus boosts edge score")
    func trustBoundaryBonus() {
        let edge = makeEdge(from: "a", to: "b", relation: .spawned, confidence: 0.9)
        let baseline = CriticalPathScorer.score(edge: edge, crossesTrustBoundary: false)
        let boosted = CriticalPathScorer.score(edge: edge, crossesTrustBoundary: true)
        #expect(boosted > baseline)
    }

    @Test("Higher confidence at same relation wins")
    func higherConfidenceWins() {
        let strong = makeEdge(from: "a", to: "b", relation: .spawned, confidence: 0.95)
        let weak = makeEdge(from: "a", to: "b", relation: .spawned, confidence: 0.5)
        #expect(CriticalPathScorer.score(edge: strong) > CriticalPathScorer.score(edge: weak))
    }

    @Test("Path scoring sums edge scores")
    func pathScoreSums() {
        let e1 = makeEdge(from: "a", to: "b", relation: .spawned, confidence: 0.9)
        let e2 = makeEdge(from: "b", to: "c", relation: .read, confidence: 0.8)
        let e3 = makeEdge(from: "c", to: "d", relation: .createdPersistence, confidence: 0.95)
        let total = CriticalPathScorer.score(path: [e1, e2, e3])
        let sum = CriticalPathScorer.score(edge: e1)
            + CriticalPathScorer.score(edge: e2)
            + CriticalPathScorer.score(edge: e3)
        #expect(total == sum)
    }

    @Test("pickCriticalPath excludes paths containing temporal-only edges")
    func pickExcludesTemporalOnly() {
        let goodPath = [
            makeEdge(from: "a", to: "b", relation: .spawned, confidence: 0.9),
            makeEdge(from: "b", to: "c", relation: .createdPersistence, confidence: 0.95),
        ]
        let temporalContaminated = [
            makeEdge(from: "a", to: "b", relation: .spawned, confidence: 0.95),
            makeEdge(from: "b", to: "c", relation: .read, confidence: 0.1),  // temporal-only
        ]
        let picked = CriticalPathScorer.pickCriticalPath(candidates: [goodPath, temporalContaminated])
        #expect(picked != nil)
        #expect(picked?.count == 2)
        #expect(picked?.allSatisfy { $0.confidenceTier != ConfidenceTier.temporalOnly.rawValue } == true)
    }

    @Test("pickCriticalPath returns nil when no path is viable")
    func pickAllTemporal() {
        let path1 = [makeEdge(from: "a", to: "b", relation: .read, confidence: 0.1)]
        let path2 = [makeEdge(from: "a", to: "b", relation: .wrote, confidence: 0.2)]
        let picked = CriticalPathScorer.pickCriticalPath(candidates: [path1, path2])
        #expect(picked == nil)
    }
}
