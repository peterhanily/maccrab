// MatchedRulesArtifact.swift
// MacCrabCore
//
// v1.10 TraceGraph (PR-11) — types for `rules/matched_rules.json`,
// the bundle artifact that records which rules fired during the
// original materialization plus their state requirements.
//
// The state-requirements field is what the ReplayEngine consults to
// decide whether a bundle is replayable inside the v1.10.0 declared
// deterministic subset (§17.1.1) or whether it must fail closed
// with `unsupported_stateful_replay` (exit 11).

import Foundation

public struct MatchedRulesArtifact: Codable, Sendable, Equatable {
    public let rules: [Rule]

    public struct Rule: Codable, Sendable, Equatable {
        public let ruleId: String
        public let ruleVersion: String
        public let severity: String
        public let matchedEventId: String?

        /// Names of stateful engines this rule's evaluation depended
        /// on (e.g. `["BehaviorScoring"]`, `["BaselineEngine"]`).
        /// Empty array means the rule is stateless and replayable.
        public let stateRequirements: [String]

        public init(
            ruleId: String,
            ruleVersion: String,
            severity: String,
            matchedEventId: String? = nil,
            stateRequirements: [String] = []
        ) {
            self.ruleId = ruleId
            self.ruleVersion = ruleVersion
            self.severity = severity
            self.matchedEventId = matchedEventId
            self.stateRequirements = stateRequirements
        }
    }

    public init(rules: [Rule]) {
        self.rules = rules
    }
}
