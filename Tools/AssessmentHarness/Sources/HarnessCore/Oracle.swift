import Foundation

// assessment-framework (P0): the deterministic verdict authority. Only an Oracle
// may set a Verdict. The orchestrating agent observes, diagnoses, and narrates —
// but never decides pass/fail. Keeping the decision here (pure, reproducible,
// later signable) is what lets a verdict be trusted independent of the agent.

/// The five terminal states a deterministic oracle can assign to an assessment.
public enum Verdict: String, Codable, Sendable {
    case pass
    case fail
    case inconclusive
    case skip
    case error
}

/// Pass/fail cut-offs an oracle compares measurements against. All optional so a
/// caller can supply only the axes it cares about; an absent threshold is not
/// evaluated. Values in `.default` are grounded in documented engine budgets
/// (50ms per-rule profiling floor, 10K partial-match cap) so the defaults are not
/// arbitrary.
public struct Thresholds: Codable, Sendable {
    public var minPrecision: Double?
    public var maxFpPerDay: Double?
    public var maxEvalP95Ms: Double?
    public var minHeldOutRecall: Double?
    public var minObfuscationCoverage: Double?
    public var maxPeakPartialMatches: Int?

    public init(
        minPrecision: Double? = nil,
        maxFpPerDay: Double? = nil,
        maxEvalP95Ms: Double? = nil,
        minHeldOutRecall: Double? = nil,
        minObfuscationCoverage: Double? = nil,
        maxPeakPartialMatches: Int? = nil
    ) {
        self.minPrecision = minPrecision
        self.maxFpPerDay = maxFpPerDay
        self.maxEvalP95Ms = maxEvalP95Ms
        self.minHeldOutRecall = minHeldOutRecall
        self.minObfuscationCoverage = minObfuscationCoverage
        self.maxPeakPartialMatches = maxPeakPartialMatches
    }

    public static let `default` = Thresholds(
        minPrecision: 0.95,
        maxFpPerDay: 5,
        maxEvalP95Ms: 50,          // matches the "rules >50ms logged" profiling budget
        minHeldOutRecall: 0.80,
        minObfuscationCoverage: 0.70,
        maxPeakPartialMatches: 10_000  // matches the sequence-engine 10K partial-match cap
    )
}

/// The output of a single oracle decision: a verdict, the raw measurements that
/// drove it (keyed by axis name), and human-readable reasons for the choice.
public struct OracleResult: Codable, Sendable {
    public let verdict: Verdict
    public let measured: [String: Double]
    public let reasons: [String]

    public init(verdict: Verdict, measured: [String: Double], reasons: [String]) {
        self.verdict = verdict
        self.measured = measured
        self.reasons = reasons
    }
}

/// A deterministic oracle: given what was observed and what was expected, plus the
/// thresholds, it returns a verdict.
///
/// - Important: `decide` MUST be pure — no I/O, no clock reads, no network. Given
///   identical `(observed, expected, thresholds)` it MUST return an identical
///   `OracleResult`. This purity is what makes verdicts reproducible and (later)
///   signable independent of the agent that triggered the observation.
public protocol Oracle: Sendable {
    associatedtype Observed: Codable & Sendable
    associatedtype Expected: Codable & Sendable

    func decide(observed: Observed, expected: Expected, thresholds: Thresholds) -> OracleResult
}
