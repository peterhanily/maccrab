// RulesetReplayer.swift
// MacCrabCore
//
// v1.10 TraceGraph (PR-11) — pluggable rule-evaluation surface for
// the ReplayEngine.
//
// Two implementations ship:
//
//   EchoRulesetReplayer — re-emits the bundle's `matched_rules.json`
//   contents as the replayed alert list. Useful as the v1.10.0
//   determinism proof (same input → same output, trivially) and as
//   a stub for tests. Stateless.
//
//   BundleEmbeddedRulesetReplayer — same as EchoRulesetReplayer
//   but with `rulesetSha256` derived from the bundle's stored
//   ruleset version, so different rulesets produce different result
//   hashes. Used by the v1.10.0 CLI's `trace replay` default path.
//
// The full integration with v1.9 RuleEngine — running rules against
// `events.jsonl` and producing a fresh alert list — is a separate
// follow-up. The plumbing here is stable; substituting a real
// replayer is a one-line change in the CLI.

import Foundation
import CryptoKit

public protocol RulesetReplayer: Sendable {
    /// Re-evaluate rules. The caller has already verified that no
    /// rule in `matchedRules` depends on a stateful engine outside
    /// the v1.10.0 declared deterministic subset.
    func replay(
        events: [String],   // raw JSONL lines, preserved order per §17.1.3
        matchedRules: [MatchedRulesArtifact.Rule]
    ) async throws -> [ReplayedAlert]

    /// SHA-256 over the ruleset definition (committed to result_sha256).
    /// Caller-supplied so tests can pin the value.
    var rulesetSha256: String { get }

    /// SHA-256 over the event normalizer (committed to result_sha256).
    var normalizerSha256: String { get }

    /// Engines this replayer can deterministically reset/hydrate.
    /// Anything outside this set + the v1.10.0 declared subset
    /// triggers the fail-closed `unsupported_stateful_replay` outcome.
    var additionallySupportedEngines: Set<String> { get }
}

// MARK: - EchoRulesetReplayer

public struct EchoRulesetReplayer: RulesetReplayer {

    public let rulesetSha256: String
    public let normalizerSha256: String
    public let additionallySupportedEngines: Set<String> = []

    public init(
        rulesetSha256: String = "echo-replayer-v1",
        normalizerSha256: String = "normalizer-v1"
    ) {
        self.rulesetSha256 = rulesetSha256
        self.normalizerSha256 = normalizerSha256
    }

    public func replay(
        events: [String],
        matchedRules: [MatchedRulesArtifact.Rule]
    ) async throws -> [ReplayedAlert] {
        matchedRules.map {
            ReplayedAlert(
                ruleId: $0.ruleId,
                ruleVersion: $0.ruleVersion,
                severity: $0.severity,
                matched: true
            )
        }
    }
}

// MARK: - BundleEmbeddedRulesetReplayer

/// Same evaluation behaviour as `EchoRulesetReplayer` but derives
/// `rulesetSha256` from a hash of the supplied ruleset identifier,
/// so two different rulesets produce different result digests.
public struct BundleEmbeddedRulesetReplayer: RulesetReplayer {

    public let rulesetSha256: String
    public let normalizerSha256: String
    public let additionallySupportedEngines: Set<String> = []

    public init(rulesetVersion: String, normalizationVersion: String) {
        let rulesetData = Data("ruleset-\(rulesetVersion)".utf8)
        let normalizerData = Data("normalizer-\(normalizationVersion)".utf8)
        self.rulesetSha256 = SHA256.hash(data: rulesetData)
            .map { String(format: "%02x", $0) }.joined()
        self.normalizerSha256 = SHA256.hash(data: normalizerData)
            .map { String(format: "%02x", $0) }.joined()
    }

    public func replay(
        events: [String],
        matchedRules: [MatchedRulesArtifact.Rule]
    ) async throws -> [ReplayedAlert] {
        matchedRules.map {
            ReplayedAlert(
                ruleId: $0.ruleId,
                ruleVersion: $0.ruleVersion,
                severity: $0.severity,
                matched: true
            )
        }
    }
}
