// RegressionOracleTests.swift
// assessment-framework (P4): pins the regression oracle — silent quality drift
// (a precision drop, an FP-rate climb, a verdict flip, a lost feature) becomes a
// deterministic red diff.

import Testing
import Foundation
@testable import HarnessCore

@Suite("Assessment P4: regression oracle")
struct RegressionOracleTests {

    private func report(_ records: [VerdictRecord]) -> AssessmentReport {
        AssessmentReport(
            schemaVersion: currentAssessmentSchemaVersion, maccrabVersion: "t", commit: "t",
            hostProfile: HostProfile(privilegeLane: "user", esEntitled: false, os: "test"),
            lanesRun: [.offlineReplay], featureVerdicts: records,
            summary: Summary(pass: 0, fail: 0, skip: 0, inconclusive: 0),
            regressions: [], evidenceBundleRef: nil, signature: nil)
    }

    private func verdict(_ id: String, _ v: Verdict, precision: Double? = nil,
                         heldOutRecall: Double? = nil, fpPerDay: Double? = nil) -> VerdictRecord {
        VerdictRecord(featureId: id, lane: .offlineReplay, triggerRef: nil,
                      expectedRuleId: nil, expectedMinSeverity: nil, observedFired: true,
                      observedAlertId: nil, verdict: v, oracle: "test",
                      measured: DetectionScore(precision: precision, heldOutRecall: heldOutRecall, fpPerDay: fpPerDay),
                      requiresRoot: false, evidenceRef: nil, timestamp: "")
    }

    @Test("Identical run has no regressions")
    func clean() {
        let base = report([verdict("r1", .pass, precision: 0.96, heldOutRecall: 0.9)])
        let cur = report([verdict("r1", .pass, precision: 0.96, heldOutRecall: 0.9)])
        #expect(RegressionOracle().diff(baseline: base, current: cur).regressed == false)
    }

    @Test("Precision drop beyond epsilon is a regression; within epsilon is not")
    func precisionDrop() {
        let base = report([verdict("r1", .pass, precision: 0.96)])
        // 0.96 → 0.80 (drop 0.16 > 0.05) regresses.
        let big = RegressionOracle().diff(baseline: base, current: report([verdict("r1", .pass, precision: 0.80)]))
        #expect(big.regressed)
        #expect(big.regressions.contains { $0.axis == "precision" && $0.now == 0.80 })
        // 0.96 → 0.93 (drop 0.03 < 0.05) does not.
        let small = RegressionOracle().diff(baseline: base, current: report([verdict("r1", .pass, precision: 0.93)]))
        #expect(small.regressed == false)
    }

    @Test("FP-rate climbing beyond epsilon is a regression (the F-04 gap as a diff)")
    func fpRise() {
        let base = report([verdict("r1", .pass, fpPerDay: 0.01)])
        let cur = report([verdict("r1", .pass, fpPerDay: 0.49)])   // 49x climb
        let r = RegressionOracle().diff(baseline: base, current: cur)
        #expect(r.regressions.contains { $0.axis == "fp_per_day" })
    }

    @Test("Verdict flip pass → fail is a regression")
    func verdictFlip() {
        let base = report([verdict("r1", .pass, precision: 0.96)])
        let cur = report([verdict("r1", .fail, precision: 0.96)])
        #expect(RegressionOracle().diff(baseline: base, current: cur).regressions.contains { $0.axis == "verdict" })
    }

    @Test("A feature covered in baseline but missing now is a coverage regression")
    func lostCoverage() {
        let base = report([verdict("r1", .pass), verdict("r2", .pass)])
        let cur = report([verdict("r1", .pass)])   // r2 dropped
        let r = RegressionOracle().diff(baseline: base, current: cur)
        #expect(r.regressions.contains { $0.ruleId == "r2" && $0.axis == "coverage" })
    }
}
