// Diagnosis.swift
// assessment-framework (P2): the find→refute discipline for the agent's
// diagnoses. When a lane fails, the AGENT (a non-deterministic LLM) proposes a
// root-cause Hypothesis — but a hypothesis becomes a reported Finding ONLY if it
// carries a falsifiable, deterministic refutation probe that CONFIRMS against the
// run's evidence. An unconfirmed hypothesis is "unverified speculation" and is
// discarded, never entered into the record. This is how LLM confabulation is
// kept out of an audit trail: the agent may claim anything, but only a
// machine-confirmed claim survives. Pure — no clock, no I/O.

import Foundation

/// A deterministic comparison the harness can run against a run's evidence map.
public struct ProbeSpec: Codable, Sendable, Equatable {
    public enum Op: String, Codable, Sendable { case lessThan, greaterThan, equalTo, notEqualTo }
    /// Key into the evidence map (e.g. a measured axis "precision", or a drop
    /// gauge "merged_priority_dropped_total").
    public let metric: String
    public let op: Op
    public let value: Double

    public init(metric: String, op: Op, value: Double) {
        self.metric = metric; self.op = op; self.value = value
    }

    /// Runs the probe. Returns nil when the metric is absent (the claim cannot
    /// be evaluated — treated as NOT confirmed, i.e. discarded).
    public func confirms(evidence: [String: Double]) -> Bool? {
        guard let actual = evidence[metric] else { return nil }
        switch op {
        case .lessThan:    return actual < value
        case .greaterThan: return actual > value
        case .equalTo:     return abs(actual - value) < 1e-9
        case .notEqualTo:  return abs(actual - value) >= 1e-9
        }
    }
}

/// An agent-proposed root cause plus the deterministic probe that must confirm it.
public struct Hypothesis: Codable, Sendable, Equatable {
    public let claim: String
    public let probe: ProbeSpec
    public init(claim: String, probe: ProbeSpec) { self.claim = claim; self.probe = probe }
}

/// A hypothesis whose probe confirmed against real evidence — the only thing
/// allowed into the diagnosis record.
public struct Finding: Codable, Sendable, Equatable {
    public let claim: String
    public let confirmedBy: ProbeSpec
    public let evidenceValue: Double
}

public enum Diagnoser {
    /// Adjudicates a hypothesis against evidence: returns a Finding iff the probe
    /// CONFIRMS; otherwise nil (the claim is unverified speculation and is dropped).
    public static func adjudicate(_ h: Hypothesis, evidence: [String: Double]) -> Finding? {
        guard h.probe.confirms(evidence: evidence) == true,
              let v = evidence[h.probe.metric] else { return nil }
        return Finding(claim: h.claim, confirmedBy: h.probe, evidenceValue: v)
    }

    /// Adjudicates a batch, returning only the confirmed findings.
    public static func adjudicate(_ hypotheses: [Hypothesis], evidence: [String: Double]) -> [Finding] {
        hypotheses.compactMap { adjudicate($0, evidence: evidence) }
    }
}
