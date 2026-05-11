// ReplayEngineTests.swift
// v1.10 TraceGraph (PR-11) — Fixtures 7 + 7b plus determinism /
// fail-closed / compatibility coverage.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("TraceGraph: ReplayEngine")
struct ReplayEngineTests {

    private let now = Date(timeIntervalSince1970: 1_700_000_000)

    // MARK: - Bundle helpers

    private func makeStore() async throws -> (SQLiteCausalGraphStore, URL) {
        let path = FileManager.default.temporaryDirectory
            .appendingPathComponent("replay-\(UUID().uuidString).db")
        return (try await SQLiteCausalGraphStore(databasePath: path.path), path)
    }

    private func makeBundle(
        matchedRules: [MatchedRulesArtifact.Rule] = [],
        eventsJsonl: [String]? = nil
    ) async throws -> URL {
        let (store, dbPath) = try await makeStore()
        defer { try? FileManager.default.removeItem(at: dbPath) }

        let proc = ProcessNode(
            processKey: "k", pid: 100, ppid: 1,
            executablePath: "/bin/zsh",
            isAppleSigned: true, isNotarized: true,
            startTime: now
        )
        let entity = try proc.toEntity(source: "test")
        try await store.upsertEntity(entity)

        let materializer = TraceMaterializer(store: store)
        let trace = try await materializer.materialize(
            anchorEntityId: entity.id,
            anchorEventId: "ev-anchor",
            title: "Replay test",
            severity: "high",
            confidence: 0.9,
            now: now.addingTimeInterval(1)
        )

        // Inputs.
        let loaded = try await store.loadTrace(id: trace.id)
        let memberships = loaded?.members ?? []

        let inputs = BundleExporter.Inputs(
            trace: trace,
            entities: [entity],
            edges: [],
            memberships: memberships,
            eventsJsonl: eventsJsonl ?? [
                #"{"event_id":"a","timestamp_ns":1700000000000000000}"#,
                #"{"event_id":"b","timestamp_ns":1700000000500000000}"#,
            ],
            policySnapshotJson: "{}",
            matchedRules: MatchedRulesArtifact(rules: matchedRules)
        )

        let bundleRoot = FileManager.default.temporaryDirectory
            .appendingPathComponent("bundle-\(UUID().uuidString)")
        let exporter = BundleExporter(
            redactor: BundleRedactor(userName: "test"),
            trustSubstrate: TrustSubstrate(
                storage: InMemoryTrustSubstrateStorage(),
                modeOverride: .filesystemDegraded
            )
        )
        try await exporter.export(inputs: inputs, to: bundleRoot)
        await store.close()
        return bundleRoot
    }

    // MARK: - Fixture 7 — replay determinism

    /// Fixture 7 from §27.2 — generate a bundle, replay twice, assert
    /// bit-identical results.
    @Test("Fixture 7: replay determinism — same bundle replayed twice is bit-identical")
    func fixture7_determinism() async throws {
        let bundle = try await makeBundle(
            matchedRules: [
                MatchedRulesArtifact.Rule(
                    ruleId: "maccrab_test_stateless",
                    ruleVersion: "1.10.0",
                    severity: "high",
                    matchedEventId: "a",
                    stateRequirements: []     // stateless — replayable
                ),
            ]
        )
        defer { try? FileManager.default.removeItem(at: bundle) }

        let engine1 = ReplayEngine()
        let engine2 = ReplayEngine()

        let r1 = try await engine1.replay(bundleAt: bundle)
        let r2 = try await engine2.replay(bundleAt: bundle)

        #expect(r1.result == .ok)
        #expect(r2.result == .ok)
        #expect(r1.deterministic)
        #expect(r2.deterministic)
        #expect(r1.alerts.count == 1)
        #expect(r2.alerts.count == 1)
        #expect(r1.alerts.first?.ruleId == "maccrab_test_stateless")

        // The load-bearing invariant: result_sha256 is identical across runs.
        #expect(r1.resultSha256 == r2.resultSha256)
        #expect(r1.exitCode == 0)
        #expect(r1 == r2, "ReplayResult must be byte-equal across runs")
    }

    // MARK: - Fixture 7b — fail-closed for unsupported stateful replay

    /// Fixture 7b from §27.2 — bundle references a rule that requires
    /// BehaviorScoring (or BaselineEngine). Replay must fail closed
    /// with `unsupported_stateful_replay`, naming the engine + rule,
    /// and the failure itself must be deterministic.
    @Test("Fixture 7b: fail-closed when a matched rule requires BehaviorScoring")
    func fixture7b_failClosed() async throws {
        let bundle = try await makeBundle(
            matchedRules: [
                MatchedRulesArtifact.Rule(
                    ruleId: "maccrab_behavior_high_risk_x",
                    ruleVersion: "1.10.0",
                    severity: "high",
                    matchedEventId: "a",
                    stateRequirements: ["BehaviorScoring"]
                ),
                MatchedRulesArtifact.Rule(
                    ruleId: "maccrab_baseline_anomaly_y",
                    ruleVersion: "1.10.0",
                    severity: "medium",
                    stateRequirements: ["BaselineEngine"]
                ),
            ]
        )
        defer { try? FileManager.default.removeItem(at: bundle) }

        let engine = ReplayEngine()
        let r1 = try await engine.replay(bundleAt: bundle)
        let r2 = try await engine.replay(bundleAt: bundle)

        #expect(r1.result == .unsupportedStatefulReplay)
        #expect(r1.deterministic)
        #expect(r1.exitCode == 11)

        // Names the offending engines + rule IDs.
        #expect(r1.unsupportedEngines.contains("BehaviorScoring"))
        #expect(r1.unsupportedEngines.contains("BaselineEngine"))
        #expect(r1.unsupportedRuleIds.contains("maccrab_behavior_high_risk_x"))
        #expect(r1.unsupportedRuleIds.contains("maccrab_baseline_anomaly_y"))

        // No partial alerts emitted (fail closed).
        #expect(r1.alerts.isEmpty)

        // The fail-closed result is itself deterministic — re-running
        // produces bit-identical output.
        #expect(r1 == r2)
        #expect(r1.resultSha256 == r2.resultSha256)
    }

    @Test("Fail-closed even when only one rule is out-of-scope")
    func partialFailClosedStillFails() async throws {
        let bundle = try await makeBundle(
            matchedRules: [
                MatchedRulesArtifact.Rule(
                    ruleId: "stateless-rule",
                    ruleVersion: "1.10.0",
                    severity: "high",
                    stateRequirements: []
                ),
                MatchedRulesArtifact.Rule(
                    ruleId: "campaign-rule",
                    ruleVersion: "1.10.0",
                    severity: "high",
                    stateRequirements: ["CampaignDetector"]
                ),
            ]
        )
        defer { try? FileManager.default.removeItem(at: bundle) }
        let engine = ReplayEngine()
        let result = try await engine.replay(bundleAt: bundle)
        #expect(result.result == .unsupportedStatefulReplay)
        #expect(result.unsupportedEngines == ["CampaignDetector"])
    }

    // MARK: - Empty matched rules

    @Test("Empty matched_rules → ok with no alerts")
    func emptyMatchedRules() async throws {
        let bundle = try await makeBundle(matchedRules: [])
        defer { try? FileManager.default.removeItem(at: bundle) }
        let engine = ReplayEngine()
        let result = try await engine.replay(bundleAt: bundle)
        #expect(result.result == .ok)
        #expect(result.alerts.isEmpty)
        #expect(result.exitCode == 0)
    }

    // MARK: - Compatibility check

    @Test("Incompatible normalization_version → outcome incompatibleNormalizationVersion (exit 6)")
    func incompatibleNormalization() async throws {
        let bundle = try await makeBundle(matchedRules: [])
        defer { try? FileManager.default.removeItem(at: bundle) }
        let engine = ReplayEngine()
        var options = ReplayEngine.ReplayOptions()
        options.expectedNormalizationVersion = "999"   // mismatches the bundle's "1"
        let result = try await engine.replay(bundleAt: bundle, options: options)
        #expect(result.result == .incompatibleNormalizationVersion)
        #expect(result.exitCode == 6)
    }

    // MARK: - Schema invalid bundle

    @Test("Schema-invalid bundle → outcome schemaInvalid (exit 1)")
    func schemaInvalidBundle() async throws {
        let bundle = try await makeBundle(matchedRules: [])
        defer { try? FileManager.default.removeItem(at: bundle) }
        // Tamper: corrupt manifest.json.
        try "{not json".write(
            to: bundle.appendingPathComponent("manifest.json"),
            atomically: true, encoding: .utf8
        )
        let engine = ReplayEngine()
        let result = try await engine.replay(bundleAt: bundle)
        #expect(result.result == .schemaInvalid)
        #expect(result.exitCode == 1)
    }

    // MARK: - Differences

    @Test("Differences detected when ruleset would no longer fire a rule")
    func differencesNewRulesetSilent() async throws {
        let bundle = try await makeBundle(
            matchedRules: [
                MatchedRulesArtifact.Rule(
                    ruleId: "old-rule", ruleVersion: "1.0.0",
                    severity: "medium", stateRequirements: []
                ),
            ]
        )
        defer { try? FileManager.default.removeItem(at: bundle) }
        // Replayer that returns NO alerts at all — simulates a newer
        // ruleset that no longer fires the original rule.
        struct SilentReplayer: RulesetReplayer {
            let rulesetSha256 = "silent-ruleset"
            let normalizerSha256 = "normalizer-v1"
            let additionallySupportedEngines: Set<String> = []
            func replay(events: [String], matchedRules: [MatchedRulesArtifact.Rule]) async throws -> [ReplayedAlert] {
                []
            }
        }
        let engine = ReplayEngine(replayer: SilentReplayer())
        let result = try await engine.replay(bundleAt: bundle)
        #expect(result.result == .ok)
        #expect(result.alerts.isEmpty)
        #expect(result.differencesVsOriginal.contains { $0.type == "rule_removed" && $0.ruleId == "old-rule" })
    }

    @Test("New rule match is reported as a difference")
    func differencesNewRuleMatch() async throws {
        let bundle = try await makeBundle(matchedRules: [])
        defer { try? FileManager.default.removeItem(at: bundle) }
        // Replayer that fires a NEW rule that wasn't in the bundle.
        struct ChattyReplayer: RulesetReplayer {
            let rulesetSha256 = "chatty-ruleset"
            let normalizerSha256 = "normalizer-v1"
            let additionallySupportedEngines: Set<String> = []
            func replay(events: [String], matchedRules: [MatchedRulesArtifact.Rule]) async throws -> [ReplayedAlert] {
                [ReplayedAlert(ruleId: "new-rule", ruleVersion: "1.10.0", severity: "high", matched: true)]
            }
        }
        let engine = ReplayEngine(replayer: ChattyReplayer())
        let result = try await engine.replay(bundleAt: bundle)
        #expect(result.result == .ok)
        #expect(result.differencesVsOriginal.contains { $0.type == "new_rule_match" && $0.ruleId == "new-rule" })
    }

    // MARK: - Canonical event ordering

    @Test("Events are reordered deterministically by (timestamp_ns, event_id)")
    func canonicalOrdering() async throws {
        // Provide events out of order; the engine should accept them.
        // We can't directly observe the ordering from ReplayResult, but
        // we can verify determinism by comparing two replays where the
        // SECOND was given the same events but in different input order.
        let outOfOrder = [
            #"{"event_id":"z","timestamp_ns":1700000000000000003}"#,
            #"{"event_id":"a","timestamp_ns":1700000000000000001}"#,
            #"{"event_id":"m","timestamp_ns":1700000000000000002}"#,
        ]
        let inOrder = [
            #"{"event_id":"a","timestamp_ns":1700000000000000001}"#,
            #"{"event_id":"m","timestamp_ns":1700000000000000002}"#,
            #"{"event_id":"z","timestamp_ns":1700000000000000003}"#,
        ]
        let bundle1 = try await makeBundle(matchedRules: [], eventsJsonl: outOfOrder)
        let bundle2 = try await makeBundle(matchedRules: [], eventsJsonl: inOrder)
        defer {
            try? FileManager.default.removeItem(at: bundle1)
            try? FileManager.default.removeItem(at: bundle2)
        }
        let engine = ReplayEngine()
        let r1 = try await engine.replay(bundleAt: bundle1)
        let r2 = try await engine.replay(bundleAt: bundle2)
        // The bundles differ in input order, but after canonical
        // ordering they're equivalent — outputs differ ONLY by the
        // bundleSha (since manifest.json differs). Result outcomes
        // should agree.
        #expect(r1.result == r2.result)
        #expect(r1.alerts == r2.alerts)
        #expect(r1.differencesVsOriginal == r2.differencesVsOriginal)
    }

    // MARK: - Exit code mapping

    // MARK: - Batch replay

    @Test("replayBatch walks a directory of bundles and aggregates results")
    func batchReplayAggregates() async throws {
        let parent = FileManager.default.temporaryDirectory
            .appendingPathComponent("batch-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: parent) }
        try FileManager.default.createDirectory(at: parent, withIntermediateDirectories: true)

        // Build three bundles: one ok, one fail-closed, one ok.
        let okRules = [
            MatchedRulesArtifact.Rule(
                ruleId: "stateless-1", ruleVersion: "1.10.0",
                severity: "high", stateRequirements: []
            )
        ]
        let failClosedRules = [
            MatchedRulesArtifact.Rule(
                ruleId: "stateful-1", ruleVersion: "1.10.0",
                severity: "high", stateRequirements: ["BehaviorScoring"]
            )
        ]

        let okBundle1 = try await makeBundle(matchedRules: okRules)
        let failBundle = try await makeBundle(matchedRules: failClosedRules)
        let okBundle2 = try await makeBundle(matchedRules: okRules)

        // Move them under `parent/<bundle-uuid>` so discoverBundles
        // sees them at the directory's top level.
        for bundle in [okBundle1, failBundle, okBundle2] {
            let destination = parent.appendingPathComponent(bundle.lastPathComponent)
            try FileManager.default.moveItem(at: bundle, to: destination)
        }

        let engine = ReplayEngine()
        let report = try await engine.replayBatch(directoryAt: parent)
        #expect(report.totalCount == 3)
        #expect(report.okCount == 2)
        #expect(report.failClosedCount == 1)
    }

    @Test("HTML report renderer emits a non-empty body referencing the directory + counts")
    func htmlReportBasics() async throws {
        let parent = FileManager.default.temporaryDirectory
            .appendingPathComponent("htmlbatch-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: parent) }
        try FileManager.default.createDirectory(at: parent, withIntermediateDirectories: true)
        let okRules = [
            MatchedRulesArtifact.Rule(ruleId: "r", ruleVersion: "1", severity: "low", stateRequirements: [])
        ]
        let bundle = try await makeBundle(matchedRules: okRules)
        let dest = parent.appendingPathComponent(bundle.lastPathComponent)
        try FileManager.default.moveItem(at: bundle, to: dest)
        let engine = ReplayEngine()
        let report = try await engine.replayBatch(directoryAt: parent)
        let html = ReplayBatchReportRenderer.renderHTML(report)
        #expect(html.contains("MacCrab TraceGraph Replay Batch Report"))
        #expect(html.contains("OK: 1"))
        #expect(html.contains(parent.lastPathComponent))
    }

    @Test("ReplayResult.exitCode follows §18.9 table")
    func exitCodeMapping() throws {
        let okResult = ReplayResult(
            traceId: "x", bundleId: "x",
            rulesetVersion: "1", daemonVersion: "1",
            normalizationVersion: "1", replayScope: "x",
            deterministic: true, result: .ok,
            inputBundleSha256: "x", rulesetSha256: "x",
            normalizerSha256: "x", replayEngineVersion: "1",
            resultSha256: "x"
        )
        #expect(okResult.exitCode == 0)

        let schemaResult = ReplayResult(
            traceId: "x", bundleId: "x",
            rulesetVersion: "1", daemonVersion: "1",
            normalizationVersion: "1", replayScope: "x",
            deterministic: true, result: .schemaInvalid,
            inputBundleSha256: "x", rulesetSha256: "x",
            normalizerSha256: "x", replayEngineVersion: "1",
            resultSha256: "x"
        )
        #expect(schemaResult.exitCode == 1)

        let normResult = ReplayResult(
            traceId: "x", bundleId: "x",
            rulesetVersion: "1", daemonVersion: "1",
            normalizationVersion: "1", replayScope: "x",
            deterministic: true, result: .incompatibleNormalizationVersion,
            inputBundleSha256: "x", rulesetSha256: "x",
            normalizerSha256: "x", replayEngineVersion: "1",
            resultSha256: "x"
        )
        #expect(normResult.exitCode == 6)

        let unsupResult = ReplayResult(
            traceId: "x", bundleId: "x",
            rulesetVersion: "1", daemonVersion: "1",
            normalizationVersion: "1", replayScope: "x",
            deterministic: true, result: .unsupportedStatefulReplay,
            inputBundleSha256: "x", rulesetSha256: "x",
            normalizerSha256: "x", replayEngineVersion: "1",
            resultSha256: "x"
        )
        #expect(unsupResult.exitCode == 11)
    }
}
