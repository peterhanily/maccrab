// ReplayEngine.swift
// MacCrabCore
//
// v1.10 TraceGraph (PR-11) — orchestrates deterministic replay of a
// `.maccrabtrace` bundle per §17 of the v1.10.0 spec.
//
// Pipeline:
//   1. Validate the bundle structurally (BundleValidator).
//   2. Load manifest + replay_manifest + matched_rules.json.
//   3. Compatibility check (§17.3) — refuse incompatible normalization_version.
//   4. State-requirement check (§17.1.1) — refuse rules outside the
//      v1.10.0 declared deterministic subset with
//      `unsupported_stateful_replay` (exit 11).
//   5. Deterministically order events by (timestamp_ns, event_id) per §17.1.3.
//   6. Hand off to the configured RulesetReplayer.
//   7. Compare against original alerts → emit differences.
//   8. Compute deterministic `result_sha256` over the canonical
//      result with the field zeroed, write it back.
//
// Out-of-scope engines explicitly named in §17.1.1:
//   BehaviorScoring, BaselineEngine, CampaignDetector,
//   SuppressionManager, rate-limit state.

import Foundation
import CryptoKit

public actor ReplayEngine {

    /// Engines v1.10.0 cannot deterministically reset/hydrate. Rules
    /// that depend on any of these trigger fail-closed replay.
    public static let outOfScopeEngines: Set<String> = [
        "BehaviorScoring",
        "BaselineEngine",
        "CampaignDetector",
        "SuppressionManager",
        "RateLimiter",
    ]

    public static var engineVersion: String { MacCrabVersion.current }

    private let replayer: RulesetReplayer
    private let engineVersion: String

    public init(
        replayer: RulesetReplayer? = nil,
        engineVersion: String = ReplayEngine.engineVersion
    ) {
        self.replayer = replayer ?? EchoRulesetReplayer()
        self.engineVersion = engineVersion
    }

    public struct ReplayOptions: Sendable {
        public var honorAttributionOverrides: Bool = false
        /// Caller may override the expected normalization version for
        /// compatibility checks. Default is the version the daemon
        /// would advertise (must match the bundle's manifest field).
        public var expectedNormalizationVersion: String = "1"

        /// A3-01: when true, run `BundleVerifier` (tamper-evidence: Merkle
        /// root + daemon signature) in addition to the structural
        /// `BundleValidator`, and fail-closed (`.schemaInvalid`) on any
        /// verify failure before replaying. The UNSIGNED placeholder bundle
        /// is exempted so unsigned dev bundles still replay for
        /// detection-engineering. Default OFF to preserve the historical
        /// replay contract (replay validates structure; verification is a
        /// separate step) and existing exit-code semantics; production
        /// callers that want fail-closed replay opt in explicitly.
        public var verifyTamperEvidence: Bool = false
        /// Trust anchor forwarded to `BundleVerifier` when
        /// `verifyTamperEvidence` is on. nil → self-contained TOFU verify.
        public var pinnedKeyFingerprint: String? = nil

        public init() {}
    }

    /// Walk a directory and replay every `.maccrabtrace` directory
    /// or `.tar.gz` archive found at the top level. Per §17.5, this
    /// is the detection-engineering platform path: regression bundles
    /// in / report out.
    public func replayBatch(
        directoryAt directory: URL,
        options: ReplayOptions = ReplayOptions(),
        now: Date = Date()
    ) async throws -> ReplayBatchReport {
        let started = now
        let candidates = try discoverBundles(in: directory)
        var entries: [ReplayBatchReport.Entry] = []
        for candidate in candidates {
            do {
                let result = try await replay(bundleAt: candidate, options: options)
                entries.append(.init(bundlePath: candidate.path, result: result))
            } catch {
                // A throw at replay-time is itself a deterministic failure;
                // construct a synthetic schemaInvalid result so the report
                // has a row for the bundle.
                let bundleSha = (try? inputBundleSha(directory: candidate)) ?? ""
                let result = ReplayResult(
                    traceId: "", bundleId: bundleSha,
                    rulesetVersion: "", daemonVersion: "",
                    normalizationVersion: "", replayScope: "",
                    deterministic: true,
                    result: .schemaInvalid,
                    inputBundleSha256: bundleSha,
                    rulesetSha256: replayer.rulesetSha256,
                    normalizerSha256: replayer.normalizerSha256,
                    replayEngineVersion: engineVersion,
                    resultSha256: "throw-\(error.localizedDescription.prefix(40))"
                )
                entries.append(.init(bundlePath: candidate.path, result: result))
            }
        }
        return ReplayBatchReport(
            runStartedAt: started,
            runCompletedAt: Date(),
            directoryPath: directory.path,
            entries: entries
        )
    }

    private func discoverBundles(in directory: URL) throws -> [URL] {
        let contents = try FileManager.default.contentsOfDirectory(
            at: directory,
            includingPropertiesForKeys: [.isDirectoryKey],
            options: [.skipsHiddenFiles]
        )
        return contents.filter { url in
            let isDir = (try? url.resourceValues(forKeys: [.isDirectoryKey]).isDirectory) ?? false
            // Bundle directories typically end in .maccrabtrace; tar.gz
            // archives are caller's responsibility to extract first
            // (the CLI handles this in `extractIfArchive`).
            if isDir { return true }
            return false
        }.sorted { $0.path < $1.path }
    }

    public func replay(
        bundleAt directory: URL,
        options: ReplayOptions = ReplayOptions()
    ) async throws -> ReplayResult {
        // Step 1 — structural validation.
        let validatorOutcome = BundleValidator.validate(at: directory)
        guard validatorOutcome.exitCode == 0 else {
            return makeFailResult(
                directory: directory,
                outcome: .schemaInvalid,
                deterministic: true,
                additionalDifferences: []
            )
        }

        // Step 1b — tamper-evidence verification (A3-01, opt-in). A bundle
        // that passes the structural validator can still have had its signed
        // artifacts rewritten; when asked, refuse to replay a tampered bundle.
        if options.verifyTamperEvidence, !isUnsignedBundle(directory: directory) {
            var verifyOptions = BundleVerifier.Options()
            verifyOptions.pinnedKeyFingerprint = options.pinnedKeyFingerprint
            let verifyOutcome = await BundleVerifier.verify(at: directory, options: verifyOptions)
            guard verifyOutcome.exitCode == 0 else {
                return makeFailResult(
                    directory: directory,
                    outcome: .schemaInvalid,
                    deterministic: true,
                    additionalDifferences: []
                )
            }
        }

        // Step 2 — load manifest + replay manifest + matched_rules.
        guard let manifest = try? loadManifest(directory: directory) else {
            return makeFailResult(
                directory: directory,
                outcome: .schemaInvalid,
                deterministic: true,
                additionalDifferences: []
            )
        }
        let replayManifest = try loadReplayManifest(directory: directory)
        let matchedRules = (try? loadMatchedRules(directory: directory)) ?? MatchedRulesArtifact(rules: [])

        let bundleSha = try inputBundleSha(directory: directory)

        // Step 3 — compatibility (§17.3).
        if manifest.normalizationVersion != options.expectedNormalizationVersion {
            return makeFailResult(
                manifest: manifest,
                replayManifest: replayManifest,
                bundleSha: bundleSha,
                outcome: .incompatibleNormalizationVersion,
                deterministic: true,
                additionalDifferences: []
            )
        }

        // Step 4 — state-requirement check (§17.1.1).
        let supportedEngines = replayer.additionallySupportedEngines
        var unsupportedRuleIds: [String] = []
        var unsupportedEngines: Set<String> = []
        for rule in matchedRules.rules {
            for engine in rule.stateRequirements {
                if Self.outOfScopeEngines.contains(engine), !supportedEngines.contains(engine) {
                    unsupportedRuleIds.append(rule.ruleId)
                    unsupportedEngines.insert(engine)
                }
            }
        }
        if !unsupportedEngines.isEmpty {
            return makeFailResult(
                manifest: manifest,
                replayManifest: replayManifest,
                bundleSha: bundleSha,
                outcome: .unsupportedStatefulReplay,
                deterministic: true,
                unsupportedEngines: Array(unsupportedEngines),
                unsupportedRuleIds: Array(Set(unsupportedRuleIds)),
                additionalDifferences: []
            )
        }

        // Step 5 — deterministic event ordering per §17.1.3.
        let orderedEvents = try canonicallyOrderedEvents(directory: directory)

        // Step 6 — hand off to the replayer.
        let replayedAlerts: [ReplayedAlert]
        do {
            replayedAlerts = try await replayer.replay(
                events: orderedEvents,
                matchedRules: matchedRules.rules
            )
        } catch {
            return makeFailResult(
                manifest: manifest,
                replayManifest: replayManifest,
                bundleSha: bundleSha,
                outcome: .schemaInvalid,
                deterministic: true,
                additionalDifferences: []
            )
        }

        // Step 7 — diff against original alerts.
        let differences = computeDifferences(
            original: matchedRules.rules,
            replayed: replayedAlerts
        )

        // Step 8 — assemble + sign.
        return try makeOkResult(
            manifest: manifest,
            replayManifest: replayManifest,
            bundleSha: bundleSha,
            alerts: replayedAlerts,
            differences: differences
        )
    }

    // MARK: - Loaders

    private func loadManifest(directory: URL) throws -> BundleManifest {
        let url = directory.appendingPathComponent("manifest.json")
        let data = try Data(contentsOf: url)
        return try canonicalJSONDecoder().decode(BundleManifest.self, from: data)
    }

    private func loadReplayManifest(directory: URL) throws -> ReplayManifestArtifact {
        let url = directory.appendingPathComponent("replay/replay_manifest.json")
        let data = try Data(contentsOf: url)
        return try canonicalJSONDecoder().decode(ReplayManifestArtifact.self, from: data)
    }

    private func loadMatchedRules(directory: URL) throws -> MatchedRulesArtifact {
        let url = directory.appendingPathComponent("rules/matched_rules.json")
        guard FileManager.default.fileExists(atPath: url.path) else {
            return MatchedRulesArtifact(rules: [])
        }
        let data = try Data(contentsOf: url)
        return try canonicalJSONDecoder().decode(MatchedRulesArtifact.self, from: data)
    }

    /// True when the bundle carries the honest UNSIGNED placeholder signature
    /// (exported without a TrustSubstrate). Such dev bundles are exempt from
    /// the opt-in tamper-evidence gate so they still replay. A missing /
    /// unreadable signature is treated as "not unsigned" so the verifier — not
    /// this shortcut — decides.
    private func isUnsignedBundle(directory: URL) -> Bool {
        let url = directory.appendingPathComponent("integrity/chain_head_signature.json")
        guard let data = try? Data(contentsOf: url),
              let sig = try? canonicalJSONDecoder().decode(ChainHeadSignatureArtifact.self, from: data)
        else { return false }
        return sig.signatureBase64 == "UNSIGNED"
    }

    private func inputBundleSha(directory: URL) throws -> String {
        // Hash the manifest content as a stable bundle identifier.
        // The full Merkle root is canonical but expensive; for the
        // replay result's `input_bundle_sha256` field a per-manifest
        // hash is enough to detect "this is the same bundle".
        let manifestURL = directory.appendingPathComponent("manifest.json")
        let data = try Data(contentsOf: manifestURL)
        return SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    private func canonicallyOrderedEvents(directory: URL) throws -> [String] {
        let url = directory.appendingPathComponent("events.jsonl")
        let text = try String(contentsOf: url, encoding: .utf8)
        let lines = text.split(omittingEmptySubsequences: true, whereSeparator: { $0.isNewline })
        // Deterministic ordering by (timestamp_ns, event_id) per §17.1.3.
        // We don't impose a Swift Codable shape on events here — the
        // ordering uses naive JSON-key extraction so the engine doesn't
        // need to know the full event schema.
        var withKeys: [(String, UInt64, String)] = []
        for line in lines {
            let lineString = String(line)
            let timestamp = extractTimestampNs(lineString) ?? 0
            let eventId = extractEventId(lineString) ?? ""
            withKeys.append((lineString, timestamp, eventId))
        }
        withKeys.sort { lhs, rhs in
            if lhs.1 != rhs.1 { return lhs.1 < rhs.1 }
            return lhs.2 < rhs.2
        }
        return withKeys.map { $0.0 }
    }

    private func extractTimestampNs(_ jsonLine: String) -> UInt64? {
        // Try common keys: timestamp_ns, ts_ns, ts, timestamp.
        guard let data = jsonLine.data(using: .utf8),
              let dict = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return nil
        }
        for key in ["timestamp_ns", "ts_ns", "ts", "timestamp"] {
            if let value = dict[key] {
                if let n = value as? UInt64 { return n }
                if let n = value as? Int64 { return UInt64(max(0, n)) }
                if let n = value as? Int { return UInt64(max(0, n)) }
                if let n = value as? Double { return UInt64(max(0, n * 1_000_000_000)) }
                if let s = value as? String, let n = UInt64(s) { return n }
            }
        }
        return nil
    }

    private func extractEventId(_ jsonLine: String) -> String? {
        guard let data = jsonLine.data(using: .utf8),
              let dict = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return nil
        }
        for key in ["event_id", "id"] {
            if let value = dict[key] as? String { return value }
        }
        return nil
    }

    // MARK: - Diff

    private func computeDifferences(
        original: [MatchedRulesArtifact.Rule],
        replayed: [ReplayedAlert]
    ) -> [ReplayDifference] {
        var diffs: [ReplayDifference] = []
        let originalById = Dictionary(uniqueKeysWithValues: original.map { ($0.ruleId, $0) })
        let replayedById = Dictionary(uniqueKeysWithValues: replayed.map { ($0.ruleId, $0) })

        // New rule matches.
        for replay in replayed {
            if originalById[replay.ruleId] == nil {
                diffs.append(ReplayDifference(type: "new_rule_match", ruleId: replay.ruleId))
            }
        }
        // Rule removed.
        for original in original {
            if replayedById[original.ruleId] == nil {
                diffs.append(ReplayDifference(type: "rule_removed", ruleId: original.ruleId))
            }
        }
        // Severity change.
        for replay in replayed {
            if let orig = originalById[replay.ruleId], orig.severity != replay.severity {
                diffs.append(ReplayDifference(
                    type: "severity_change",
                    ruleId: replay.ruleId,
                    from: orig.severity,
                    to: replay.severity
                ))
            }
        }
        return diffs
    }

    // MARK: - Result builders

    private func makeOkResult(
        manifest: BundleManifest,
        replayManifest: ReplayManifestArtifact,
        bundleSha: String,
        alerts: [ReplayedAlert],
        differences: [ReplayDifference]
    ) throws -> ReplayResult {
        let partial = ReplayResult(
            traceId: manifest.traceId,
            bundleId: bundleSha,
            rulesetVersion: manifest.rulesetVersion,
            daemonVersion: manifest.maccrabVersion,
            normalizationVersion: manifest.normalizationVersion,
            replayScope: replayManifest.replayScope,
            deterministic: true,
            result: .ok,
            alerts: alerts,
            unsupportedEngines: [],
            unsupportedRuleIds: [],
            differencesVsOriginal: differences,
            inputBundleSha256: bundleSha,
            rulesetSha256: replayer.rulesetSha256,
            normalizerSha256: replayer.normalizerSha256,
            replayEngineVersion: engineVersion,
            resultSha256: ""
        )
        let digest = try ReplayResultDigest.compute(for: partial)
        return ReplayResult(
            traceId: partial.traceId,
            bundleId: partial.bundleId,
            rulesetVersion: partial.rulesetVersion,
            daemonVersion: partial.daemonVersion,
            normalizationVersion: partial.normalizationVersion,
            replayScope: partial.replayScope,
            deterministic: true,
            result: .ok,
            alerts: partial.alerts,
            unsupportedEngines: [],
            unsupportedRuleIds: [],
            differencesVsOriginal: partial.differencesVsOriginal,
            inputBundleSha256: partial.inputBundleSha256,
            rulesetSha256: partial.rulesetSha256,
            normalizerSha256: partial.normalizerSha256,
            replayEngineVersion: partial.replayEngineVersion,
            resultSha256: digest
        )
    }

    /// Build a fail-closed (or compatibility-failure) result.
    /// Determinism still holds — re-running produces bit-identical output.
    private func makeFailResult(
        manifest: BundleManifest? = nil,
        replayManifest: ReplayManifestArtifact? = nil,
        bundleSha: String? = nil,
        directory: URL? = nil,
        outcome: ReplayResult.Outcome,
        deterministic: Bool,
        unsupportedEngines: [String] = [],
        unsupportedRuleIds: [String] = [],
        additionalDifferences: [ReplayDifference]
    ) -> ReplayResult {
        let bundleSha = bundleSha ?? (directory.flatMap { try? inputBundleSha(directory: $0) } ?? "")
        let partial = ReplayResult(
            traceId: manifest?.traceId ?? "",
            bundleId: bundleSha,
            rulesetVersion: manifest?.rulesetVersion ?? "",
            daemonVersion: manifest?.maccrabVersion ?? "",
            normalizationVersion: manifest?.normalizationVersion ?? "",
            replayScope: replayManifest?.replayScope ?? "declared_deterministic_subset",
            deterministic: deterministic,
            result: outcome,
            alerts: [],
            unsupportedEngines: unsupportedEngines,
            unsupportedRuleIds: unsupportedRuleIds,
            differencesVsOriginal: additionalDifferences,
            inputBundleSha256: bundleSha,
            rulesetSha256: replayer.rulesetSha256,
            normalizerSha256: replayer.normalizerSha256,
            replayEngineVersion: engineVersion,
            resultSha256: ""
        )
        let digest = (try? ReplayResultDigest.compute(for: partial)) ?? "compute_failed"
        return ReplayResult(
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
            resultSha256: digest
        )
    }
}
