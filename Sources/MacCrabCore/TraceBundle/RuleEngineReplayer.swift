// RuleEngineReplayer.swift
// MacCrabCore
//
// The real replayer. `RulesetReplayer.swift` ships two implementations that
// both ignore their `events` argument entirely and re-emit the bundle's
// recorded `matched_rules.json`. That is a determinism proof and nothing
// more: it cannot tell you whether today's ruleset still detects what
// yesterday's did, because it never runs a rule. Its own header calls the
// integration with RuleEngine "a separate follow-up".
//
// This is that follow-up. It decodes each `events.jsonl` line into the
// daemon's normalized `Event` and drives the real `RuleEngine` over it, so
// the replayed alert list is a FRESH result produced by the ruleset under
// test — which is what makes a replay differ from a recording, and what
// makes regression comparison mean anything.
//
// SCOPE, DELIBERATELY NARROW
//   Single-event, stateless rule evaluation only. `additionallySupportedEngines`
//   stays empty, so a bundle whose matched rules declare a dependency on
//   BehaviorScoring, BaselineEngine, the sequence engine, or any other stateful
//   surface still takes the caller's fail-closed `unsupported_stateful_replay`
//   path rather than being silently under-evaluated here. Widening this set is
//   a decision about hydration, not a decision about this file.

import Foundation
import CryptoKit

public struct RuleEngineReplayer: RulesetReplayer {

    public let rulesetSha256: String
    public let normalizerSha256: String
    public let additionallySupportedEngines: Set<String> = []

    private let rulesDirectory: URL
    private let enabledStatuses: Set<String>?

    /// Version stamped on the normalization path — the `Event` decode used
    /// here. Bump when that decode changes shape in a way that could alter a
    /// replay result, so old and new results hash differently instead of
    /// silently comparing as equal.
    private static let normalizerVersion = "rule-engine-replayer-normalizer-v1"

    public enum ReplayError: Error, CustomStringConvertible {
        case unreadableRulesDirectory(URL)
        case emptyRuleset(URL)
        case undecodableEventLine(index: Int, underlying: String)

        public var description: String {
            switch self {
            case .unreadableRulesDirectory(let url):
                return "compiled-rules directory is unreadable: \(url.path)"
            case .emptyRuleset(let url):
                return "compiled-rules directory contains no rules: \(url.path)"
            case .undecodableEventLine(let index, let underlying):
                return "events.jsonl line \(index + 1) did not decode as an Event: \(underlying)"
            }
        }
    }

    /// - Parameters:
    ///   - rulesDirectory: compiled-rules directory (the `compile_rules.py`
    ///     output shape the daemon loads).
    ///   - enabledStatuses: rule-status gate, matching `RuleEngine.loadRules`.
    ///     `nil` loads everything the directory contains. Pass the profile the
    ///     result is meant to describe — a replay under `stable` and a replay
    ///     under `all` are different measurements and must not be compared.
    public init(rulesDirectory: URL, enabledStatuses: Set<String>? = nil) throws {
        self.rulesDirectory = rulesDirectory
        self.enabledStatuses = enabledStatuses
        self.normalizerSha256 = Self.hex(SHA256.hash(data: Data(Self.normalizerVersion.utf8)))
        self.rulesetSha256 = try Self.digestRuleset(at: rulesDirectory, statuses: enabledStatuses)
    }

    /// SHA-256 over the actual compiled-rule bytes, in sorted-path order, with
    /// the status gate folded in.
    ///
    /// `BundleEmbeddedRulesetReplayer` hashes a version *string*, so two
    /// genuinely different rulesets that share a version label collide and
    /// compare as identical. Hashing the content means the digest changes when
    /// the rules change — which is the only property that makes committing it
    /// to `result_sha256` worth anything.
    private static func digestRuleset(at directory: URL, statuses: Set<String>?) throws -> String {
        let fm = FileManager.default
        guard let entries = try? fm.contentsOfDirectory(
            at: directory, includingPropertiesForKeys: nil, options: [.skipsHiddenFiles]
        ) else {
            throw ReplayError.unreadableRulesDirectory(directory)
        }
        let ruleFiles = entries
            .filter { $0.pathExtension.lowercased() == "json" }
            .sorted { $0.lastPathComponent < $1.lastPathComponent }
        guard !ruleFiles.isEmpty else { throw ReplayError.emptyRuleset(directory) }

        var hasher = SHA256()
        // The status gate changes which rules evaluate, so it changes the
        // result and belongs in the digest.
        let gate = statuses.map { $0.sorted().joined(separator: ",") } ?? "*"
        hasher.update(data: Data("statuses:\(gate)\n".utf8))
        for file in ruleFiles {
            hasher.update(data: Data("\(file.lastPathComponent)\n".utf8))
            if let bytes = try? Data(contentsOf: file) {
                hasher.update(data: bytes)
            }
        }
        return hex(hasher.finalize())
    }

    private static func hex<D: Sequence>(_ digest: D) -> String where D.Element == UInt8 {
        digest.map { String(format: "%02x", $0) }.joined()
    }

    public func replay(
        events: [String],
        matchedRules: [MatchedRulesArtifact.Rule]
    ) async throws -> [ReplayedAlert] {
        let engine = RuleEngine()
        _ = try await engine.loadRules(from: rulesDirectory, enabledStatuses: enabledStatuses)

        let decoder = JSONDecoder()
        // Order is the caller's contract (§17.1.3: sorted by timestamp_ns,
        // event_id). Preserve it rather than re-sorting — re-sorting here
        // would mask a caller that failed to order its input.
        var firedOrder: [String] = []
        var firedByRule: [String: RuleMatch] = [:]

        for (index, line) in events.enumerated() {
            let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
            if trimmed.isEmpty { continue }
            guard let data = trimmed.data(using: .utf8) else {
                throw ReplayError.undecodableEventLine(index: index, underlying: "not valid UTF-8")
            }
            let event: Event
            do {
                event = try decoder.decode(Event.self, from: data)
            } catch {
                // Fail loud. A skipped line is a silently smaller corpus, and
                // a smaller corpus makes recall look better than it is.
                throw ReplayError.undecodableEventLine(index: index, underlying: String(describing: error))
            }

            for match in await engine.evaluate(event) {
                // One entry per RULE, not per (rule, event): `matched_rules.json`
                // is a set of rules, so a comparable replay result is too.
                // ReplayedAlert carries no event id, so per-occurrence entries
                // would be indistinguishable duplicates anyway.
                if firedByRule[match.ruleId] == nil {
                    firedByRule[match.ruleId] = match
                    firedOrder.append(match.ruleId)
                }
            }
        }

        // The version is the ruleset that produced THIS result, not the one
        // recorded in the bundle. Carrying the recorded version forward would
        // label a fresh result with the ruleset that never ran — precisely the
        // confusion a replay exists to prevent.
        let version = "ruleset-\(rulesetSha256.prefix(12))"
        return firedOrder.compactMap { ruleId in
            guard let match = firedByRule[ruleId] else { return nil }
            return ReplayedAlert(
                ruleId: match.ruleId,
                ruleVersion: version,
                severity: match.severity.rawValue,
                matched: true
            )
        }
    }
}
