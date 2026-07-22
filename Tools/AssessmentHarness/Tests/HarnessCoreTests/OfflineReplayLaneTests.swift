// OfflineReplayLaneTests.swift
// assessment-framework (P1): pins the Lane-1 vertical slice — the reverse-shell
// rule must score perfectly on the labeled corpus (fidelity: synthetic events
// match what the real rule reads), the run must be deterministic, and the
// oracle must decide from the score alone.

import Testing
import Foundation
@testable import HarnessCore

@Suite("Assessment P1: offline replay (T1059.004 reverse shell)")
struct OfflineReplayLaneTests {

    @Test("Reverse-shell rule scores perfectly on the labeled corpus")
    func perfectScore() async throws {
        let score = try await OfflineReplayLane().run(corpus: Corpora.reverseShell)
        // Every positive (visible + held-out, across representations) must fire;
        // no benign near-miss may. If this fails the corpus/Event fidelity is
        // wrong, not the assertion.
        #expect(score.tp == 9)
        #expect(score.fp == 0)
        #expect(score.fn == 0)
        #expect(score.precision == 1.0)
        #expect(score.recall == 1.0)            // visible variants
        #expect(score.heldOutRecall == 1.0)     // novel variants — generalization
        #expect(score.obfuscationCoverage == 1.0)
        #expect(score.metadataComplete == true)
    }

    @Test("Run is deterministic — identical measured score across two runs")
    func determinism() async throws {
        let lane = OfflineReplayLane()
        let a = try await lane.run(corpus: Corpora.reverseShell)
        let b = try await lane.run(corpus: Corpora.reverseShell)
        #expect(a.precision == b.precision)
        #expect(a.recall == b.recall)
        #expect(a.heldOutRecall == b.heldOutRecall)
        #expect(a.obfuscationCoverage == b.obfuscationCoverage)
        #expect(a.tp == b.tp && a.fp == b.fp && a.fn == b.fn)
    }

    @Test("Precision oracle passes a strong score under default thresholds")
    func oraclePass() throws {
        let score = DetectionScore(precision: 1.0, recall: 1.0, heldOutRecall: 1.0,
                                   obfuscationCoverage: 1.0, metadataComplete: true)
        let r = PrecisionOracle().decide(observed: score,
                                         expected: .init(technique: "T1059.004"),
                                         thresholds: .default)
        #expect(r.verdict == .pass)
        #expect(r.measured["precision"] == 1.0)
    }

    @Test("Oracle returns inconclusive when a gated axis is unmeasured")
    func oracleInconclusive() throws {
        // precision present but held_out_recall nil while the default bar requires it.
        let score = DetectionScore(precision: 1.0, obfuscationCoverage: 1.0)
        let r = PrecisionOracle().decide(observed: score,
                                         expected: .init(technique: "T1059.004"),
                                         thresholds: .default)
        #expect(r.verdict == .inconclusive)
    }

    @Test("Oracle fails a weak score")
    func oracleFail() throws {
        let score = DetectionScore(precision: 0.4, recall: 1.0, heldOutRecall: 0.2,
                                   obfuscationCoverage: 0.3)
        let r = PrecisionOracle().decide(observed: score,
                                         expected: .init(technique: "T1059.004"),
                                         thresholds: .default)
        #expect(r.verdict == .fail)
    }
}
