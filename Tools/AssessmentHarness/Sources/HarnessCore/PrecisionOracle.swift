// PrecisionOracle.swift
// assessment-framework (P1): the deterministic verdict authority for the
// detection-engineering score. Pure — no clock, no I/O, no LLM. The same score
// + thresholds always yields the same verdict, so the result can be signed and
// regression-baselined. An agent may CHOOSE what to run and diagnose failures,
// but the verdict comes only from here.

import Foundation

/// Expected side of the precision judgement. The concrete bar lives in
/// `Thresholds`; this type exists to satisfy the `Oracle` associated type and
/// carries the technique label for provenance.
public struct DetectionExpectation: Codable, Sendable {
    public let technique: String
    public init(technique: String) { self.technique = technique }
}

public struct PrecisionOracle: Oracle {
    public typealias Observed = DetectionScore
    public typealias Expected = DetectionExpectation

    public init() {}

    public func decide(observed: DetectionScore,
                       expected: DetectionExpectation,
                       thresholds: Thresholds) -> OracleResult {
        var measured: [String: Double] = [:]
        if let p = observed.precision { measured["precision"] = p }
        if let r = observed.recall { measured["recall"] = r }
        if let hr = observed.heldOutRecall { measured["held_out_recall"] = hr }
        if let oc = observed.obfuscationCoverage { measured["obfuscation_coverage"] = oc }

        var reasons: [String] = []
        var inconclusive = false

        /// A required min-axis check. Returns nil (and marks the run
        /// inconclusive) when a threshold is set but no measurement exists —
        /// the framework refuses to call an unmeasured axis a pass.
        func requireMin(_ value: Double?, _ bar: Double?, _ name: String) -> Bool? {
            guard let bar else { return true }               // no bar → axis not gated
            guard let value else {
                inconclusive = true
                reasons.append("\(name): threshold \(bar) set but no measurement")
                return nil
            }
            if value + 1e-9 >= bar { return true }
            reasons.append("\(name) \(fmt(value)) < required \(fmt(bar))")
            return false
        }

        let checks = [
            requireMin(observed.precision, thresholds.minPrecision, "precision"),
            requireMin(observed.heldOutRecall, thresholds.minHeldOutRecall, "held_out_recall"),
            requireMin(observed.obfuscationCoverage, thresholds.minObfuscationCoverage, "obfuscation_coverage"),
        ]

        let verdict: Verdict
        if inconclusive {
            verdict = .inconclusive
        } else if checks.compactMap({ $0 }).allSatisfy({ $0 }) {
            verdict = .pass
            reasons.append("all required axes cleared for \(expected.technique)")
        } else {
            verdict = .fail
        }
        return OracleResult(verdict: verdict, measured: measured, reasons: reasons)
    }

    private func fmt(_ d: Double) -> String { String(format: "%.3f", d) }
}
