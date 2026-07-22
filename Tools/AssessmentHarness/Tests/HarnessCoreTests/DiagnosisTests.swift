// DiagnosisTests.swift
// assessment-framework (P2): the find→refute discipline and the diagnoser
// meta-eval, both deterministic.

import Testing
import Foundation
@testable import HarnessCore

@Suite("Assessment P2: find→refute + meta-eval")
struct DiagnosisTests {

    @Test("A hypothesis whose probe confirms becomes a finding")
    func confirmed() {
        // Claim: the sensor dropped priority events under load.
        let h = Hypothesis(claim: "priority stream dropped events",
                           probe: ProbeSpec(metric: "merged_priority_dropped_total", op: .greaterThan, value: 0))
        let finding = Diagnoser.adjudicate(h, evidence: ["merged_priority_dropped_total": 37])
        #expect(finding != nil)
        #expect(finding?.evidenceValue == 37)
    }

    @Test("A hypothesis whose probe fails is discarded (unverified speculation)")
    func discarded() {
        let h = Hypothesis(claim: "priority stream dropped events",
                           probe: ProbeSpec(metric: "merged_priority_dropped_total", op: .greaterThan, value: 0))
        // Evidence contradicts the claim — zero drops.
        #expect(Diagnoser.adjudicate(h, evidence: ["merged_priority_dropped_total": 0]) == nil)
    }

    @Test("A hypothesis about an absent metric cannot be confirmed")
    func absentMetric() {
        let h = Hypothesis(claim: "eval latency spiked",
                           probe: ProbeSpec(metric: "eval_p95_ms", op: .greaterThan, value: 50))
        #expect(Diagnoser.adjudicate(h, evidence: ["precision": 1.0]) == nil)
    }

    @Test("Batch adjudication keeps only confirmed findings")
    func batch() {
        let confirmed = Hypothesis(claim: "precision collapsed",
                                   probe: ProbeSpec(metric: "precision", op: .lessThan, value: 0.9))
        let bogus = Hypothesis(claim: "recall collapsed",
                               probe: ProbeSpec(metric: "recall", op: .lessThan, value: 0.5))
        let findings = Diagnoser.adjudicate([confirmed, bogus],
                                            evidence: ["precision": 0.42, "recall": 1.0])
        #expect(findings.count == 1)
        #expect(findings.first?.claim == "precision collapsed")
    }

    @Test("Meta-eval scores an exact and an acceptable-action root cause as correct")
    func metaScore() {
        let fx = DiagnosisMetaEval.seedFixtures.first { $0.label == "sensor-drop-under-burst" }!
        #expect(DiagnosisMetaEval.score(proposedRootCause: "priority-stream-backpressure", fixture: fx) == 1.0)
        #expect(DiagnosisMetaEval.score(proposedRootCause: "increase merged_priority_stream_cap", fixture: fx) == 1.0)
        #expect(DiagnosisMetaEval.score(proposedRootCause: "disk full", fixture: fx) == 0.0)
    }

    @Test("A perfect diagnoser passes the 0.8 gate; a poor one fails")
    func metaAccuracyGate() {
        let good = DiagnosisMetaEval.seedFixtures.map { (proposed: $0.expectedRootCause, fixture: $0) }
        let goodAcc = DiagnosisMetaEval.accuracy(good)
        #expect(goodAcc == 1.0)
        #expect(DiagnosisMetaEval.passes(accuracy: goodAcc))

        let bad = DiagnosisMetaEval.seedFixtures.map { (proposed: "unrelated", fixture: $0) }
        #expect(DiagnosisMetaEval.passes(accuracy: DiagnosisMetaEval.accuracy(bad)) == false)
    }
}
