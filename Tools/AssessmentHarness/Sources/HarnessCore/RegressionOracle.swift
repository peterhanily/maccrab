// RegressionOracle.swift
// assessment-framework (P4): the deterministic regression oracle. Diffs a
// current assessment run against a checked-in baseline and flags silent quality
// drift — a per-rule score axis dropping beyond epsilon, an FP-rate climbing, a
// verdict flipping pass→fail, or a feature that was covered becoming absent.
// This is what turns "found by a one-off audit" into "a red CI diff": absolute
// thresholds (in PrecisionOracle) catch the floor; baseline-delta catches the
// trend. Pure — no clock, no I/O.

import Foundation

public struct RegressionOracle: Sendable {

    /// How much a "higher is better" axis may drop before it is a regression.
    public var epsilon: Double
    public init(epsilon: Double = 0.05) { self.epsilon = epsilon }

    public struct Result: Sendable {
        public let regressions: [Regression]
        /// A run regresses if any regression was found.
        public var regressed: Bool { !regressions.isEmpty }
    }

    /// Diff `current` against `baseline`. Both are keyed by VerdictRecord.featureId.
    public func diff(baseline: AssessmentReport, current: AssessmentReport) -> Result {
        var regressions: [Regression] = []
        let curByFeature = Dictionary(current.featureVerdicts.map { ($0.featureId, $0) },
                                      uniquingKeysWith: { a, _ in a })

        for base in baseline.featureVerdicts {
            guard let cur = curByFeature[base.featureId] else {
                // A feature that was assessed in the baseline is missing now —
                // silent coverage loss is itself a regression.
                regressions.append(Regression(ruleId: base.featureId, axis: "coverage",
                                               was: 1, now: 0))
                continue
            }
            // Verdict flip pass → fail/inconclusive.
            if base.verdict == .pass && cur.verdict != .pass {
                regressions.append(Regression(ruleId: base.featureId, axis: "verdict",
                                              was: 1, now: 0))
            }
            // Higher-is-better axes: regression when they DROP by > epsilon.
            checkDrop(&regressions, base.featureId, "precision", base.measured.precision, cur.measured.precision)
            checkDrop(&regressions, base.featureId, "recall", base.measured.recall, cur.measured.recall)
            checkDrop(&regressions, base.featureId, "held_out_recall", base.measured.heldOutRecall, cur.measured.heldOutRecall)
            checkDrop(&regressions, base.featureId, "obfuscation_coverage", base.measured.obfuscationCoverage, cur.measured.obfuscationCoverage)
            // Lower-is-better axes: regression when they RISE by > epsilon.
            checkRise(&regressions, base.featureId, "fp_per_day", base.measured.fpPerDay, cur.measured.fpPerDay)
            checkRise(&regressions, base.featureId, "eval_p95_ms", base.measured.evalP95Ms, cur.measured.evalP95Ms, epsilonScale: 1.0)
        }
        return Result(regressions: regressions)
    }

    private func checkDrop(_ acc: inout [Regression], _ id: String, _ axis: String,
                           _ was: Double?, _ now: Double?) {
        guard let was, let now else { return }   // can't compare if either side is unmeasured
        if now < was - epsilon {
            acc.append(Regression(ruleId: id, axis: axis, was: was, now: now))
        }
    }

    private func checkRise(_ acc: inout [Regression], _ id: String, _ axis: String,
                           _ was: Double?, _ now: Double?, epsilonScale: Double = 1.0) {
        guard let was, let now else { return }
        if now > was + epsilon * epsilonScale {
            acc.append(Regression(ruleId: id, axis: axis, was: was, now: now))
        }
    }
}
