// ReplayResult.swift
// MacCrabCore
//
// v1.10 TraceGraph (PR-11) — canonical result type for ReplayEngine
// per §17.4 of the v1.10.0 spec.
//
// Two valid shapes:
//
//   `ok` outcome — the rules were re-evaluated against the bundle's
//   events and produced a deterministic alert list. `result_sha256`
//   is the SHA-256 of the canonical JSON of the result with that
//   field excluded; running replay twice on the same input produces
//   identical bytes.
//
//   `unsupported_stateful_replay` outcome — at least one matched
//   rule requires a stateful engine outside the v1.10.0 declared
//   deterministic subset. The result names the offending engines and
//   rule IDs and is itself deterministic (re-running produces
//   bit-identical output).

import Foundation
import CryptoKit

public struct ReplayedAlert: Codable, Sendable, Equatable {
    public let ruleId: String
    public let ruleVersion: String
    public let severity: String
    public let matched: Bool

    public init(ruleId: String, ruleVersion: String, severity: String, matched: Bool) {
        self.ruleId = ruleId
        self.ruleVersion = ruleVersion
        self.severity = severity
        self.matched = matched
    }
}

public struct ReplayDifference: Codable, Sendable, Equatable {
    public let type: String         // "new_rule_match" | "severity_change" | "rule_removed"
    public let ruleId: String
    public let from: String?
    public let to: String?

    public init(type: String, ruleId: String, from: String? = nil, to: String? = nil) {
        self.type = type
        self.ruleId = ruleId
        self.from = from
        self.to = to
    }
}

public struct ReplayResult: Codable, Sendable, Equatable {

    public enum Outcome: String, Codable, Sendable, Equatable {
        case ok
        case unsupportedStatefulReplay = "unsupported_stateful_replay"
        case incompatibleNormalizationVersion = "incompatible_normalization_version"
        case schemaInvalid = "schema_invalid"
    }

    public let traceId: String
    public let bundleId: String
    public let rulesetVersion: String
    public let daemonVersion: String
    public let normalizationVersion: String
    public let replayScope: String
    public let deterministic: Bool
    public let result: Outcome
    public let alerts: [ReplayedAlert]
    public let unsupportedEngines: [String]
    public let unsupportedRuleIds: [String]
    public let differencesVsOriginal: [ReplayDifference]
    public let inputBundleSha256: String
    public let rulesetSha256: String
    public let normalizerSha256: String
    public let replayEngineVersion: String
    public let resultSha256: String

    public init(
        traceId: String,
        bundleId: String,
        rulesetVersion: String,
        daemonVersion: String,
        normalizationVersion: String,
        replayScope: String,
        deterministic: Bool,
        result: Outcome,
        alerts: [ReplayedAlert] = [],
        unsupportedEngines: [String] = [],
        unsupportedRuleIds: [String] = [],
        differencesVsOriginal: [ReplayDifference] = [],
        inputBundleSha256: String,
        rulesetSha256: String,
        normalizerSha256: String,
        replayEngineVersion: String,
        resultSha256: String
    ) {
        self.traceId = traceId
        self.bundleId = bundleId
        self.rulesetVersion = rulesetVersion
        self.daemonVersion = daemonVersion
        self.normalizationVersion = normalizationVersion
        self.replayScope = replayScope
        self.deterministic = deterministic
        self.result = result
        self.alerts = alerts.sorted(by: { $0.ruleId < $1.ruleId })
        self.unsupportedEngines = unsupportedEngines.sorted()
        self.unsupportedRuleIds = unsupportedRuleIds.sorted()
        self.differencesVsOriginal = differencesVsOriginal.sorted(by: { $0.ruleId < $1.ruleId })
        self.inputBundleSha256 = inputBundleSha256
        self.rulesetSha256 = rulesetSha256
        self.normalizerSha256 = normalizerSha256
        self.replayEngineVersion = replayEngineVersion
        self.resultSha256 = resultSha256
    }

    /// Map ReplayResult.result to the v1.10.0 §18.9 stable exit codes.
    /// `ok` → 0; `unsupported_stateful_replay` → 11;
    /// `incompatible_normalization_version` → 6; `schema_invalid` → 1.
    public var exitCode: Int32 {
        switch result {
        case .ok:                                  return 0
        case .schemaInvalid:                       return 1
        case .incompatibleNormalizationVersion:    return 6
        case .unsupportedStatefulReplay:           return 11
        }
    }
}

// MARK: - Deterministic result_sha256 computation

public enum ReplayResultDigest {

    /// Build the canonical JSON representation of a result with the
    /// `result_sha256` field set to a sentinel; SHA-256 of those
    /// bytes is what gets stored back into `result_sha256`. Running
    /// twice on the same input produces an identical hash, which is
    /// the determinism contract (§17.1).
    public static func compute(for partial: ReplayResult) throws -> String {
        let withSentinel = ReplayResult(
            traceId: partial.traceId,
            bundleId: partial.bundleId,
            rulesetVersion: partial.rulesetVersion,
            daemonVersion: partial.daemonVersion,
            normalizationVersion: partial.normalizationVersion,
            replayScope: partial.replayScope,
            deterministic: partial.deterministic,
            result: partial.result,
            alerts: partial.alerts,
            unsupportedEngines: partial.unsupportedEngines,
            unsupportedRuleIds: partial.unsupportedRuleIds,
            differencesVsOriginal: partial.differencesVsOriginal,
            inputBundleSha256: partial.inputBundleSha256,
            rulesetSha256: partial.rulesetSha256,
            normalizerSha256: partial.normalizerSha256,
            replayEngineVersion: partial.replayEngineVersion,
            resultSha256: ""    // sentinel
        )
        let encoder = canonicalJSONEncoder()
        let data = try encoder.encode(withSentinel)
        return SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }
}
