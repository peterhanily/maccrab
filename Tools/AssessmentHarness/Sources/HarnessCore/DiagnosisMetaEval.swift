// DiagnosisMetaEval.swift
// assessment-framework (P2): the framework evaluating its own evaluator. Before
// the AI diagnoser is trusted to explain product failures, it passes a labeled
// exam — the same discipline the LLM alert-triage eval already uses in
// MacCrabCore's LLMEvalTests, generalized from alert-verdict labels to
// root-cause labels. The diagnoser's accuracy is itself a MEASURED, gated,
// baselineable number (an unmeasured diagnoser is a documented-coverage claim
// about the diagnoser — the exact anti-pattern the framework eliminates one
// level up). The scoring math is deterministic; no LLM decides the grade.

import Foundation

/// One labeled diagnosis case: a lane result and the root cause a correct
/// diagnoser should identify.
public struct DiagnosisFixture: Codable, Sendable, Equatable {
    public let label: String
    /// The evidence a diagnoser would see (measured axes + gauges).
    public let evidence: [String: Double]
    /// The expected root-cause tag (canonical form).
    public let expectedRootCause: String
    /// Alternate acceptable root-cause tags / remediation actions.
    public let acceptableActions: [String]

    public init(label: String, evidence: [String: Double],
                expectedRootCause: String, acceptableActions: [String] = []) {
        self.label = label; self.evidence = evidence
        self.expectedRootCause = expectedRootCause; self.acceptableActions = acceptableActions
    }
}

public enum DiagnosisMetaEval {
    /// The pass bar for the diagnoser (mirrors the design's ≥0.8 gate).
    public static let passThreshold = 0.8

    private static func normalize(_ s: String) -> String {
        s.lowercased().trimmingCharacters(in: .whitespacesAndNewlines)
    }

    /// Scores one proposed root cause against a fixture: 1.0 if it matches the
    /// expected root cause OR any acceptable action (case-insensitive,
    /// whitespace-trimmed), else 0.0. Deterministic — no model in the grade.
    public static func score(proposedRootCause: String, fixture: DiagnosisFixture) -> Double {
        let p = normalize(proposedRootCause)
        let accepted = ([fixture.expectedRootCause] + fixture.acceptableActions).map(normalize)
        return accepted.contains(p) ? 1.0 : 0.0
    }

    /// Mean score over (proposed, fixture) pairs — the diagnoser's accuracy.
    public static func accuracy(_ graded: [(proposed: String, fixture: DiagnosisFixture)]) -> Double {
        guard !graded.isEmpty else { return 0 }
        let total = graded.reduce(0.0) { $0 + score(proposedRootCause: $1.proposed, fixture: $1.fixture) }
        return total / Double(graded.count)
    }

    /// Whether an accuracy clears the gate.
    public static func passes(accuracy: Double) -> Bool { accuracy + 1e-9 >= passThreshold }

    /// A small seed corpus (grows over time). These mirror real failure modes
    /// the framework's own lanes surface.
    public static let seedFixtures: [DiagnosisFixture] = [
        DiagnosisFixture(
            label: "sensor-drop-under-burst",
            evidence: ["merged_priority_dropped_total": 37, "es_kernel_dropped_total": 0],
            expectedRootCause: "priority-stream-backpressure",
            acceptableActions: ["increase merged_priority_stream_cap", "reduce ES copy backpressure"]),
        DiagnosisFixture(
            label: "precision-collapse",
            evidence: ["precision": 0.42, "recall": 1.0],
            expectedRootCause: "over-broad-rule-predicate",
            acceptableActions: ["tighten rule selection", "add a filter block"]),
        DiagnosisFixture(
            label: "held-out-recall-gap",
            evidence: ["precision": 1.0, "held_out_recall": 0.3, "recall": 1.0],
            expectedRootCause: "memorized-not-generalized",
            acceptableActions: ["generalize the rule to variant representations"]),
    ]
}
