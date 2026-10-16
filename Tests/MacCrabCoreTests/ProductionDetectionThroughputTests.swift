import CryptoKit
import Foundation
import Testing
@testable import MacCrabCore

/// Real production evaluators, inert records only. No collector, enrichment,
/// response action, installed store or host workload is started. Compilation,
/// corpus validation, fixtures and telemetry persistence are outside timing.
@Suite("Production detection synthetic throughput", .serialized)
struct ProductionDetectionThroughputTests {
    private let profile: Set<String> = ["stable"]
    private let batchSize = 512
    private struct Corpus {
        let digest: String
        let singles: [CompiledRule]
        let sequences: [SequenceRule]
    }

    private func corpus(at root: URL) throws -> Corpus {
        var hash = SHA256()
        hash.update(data: Data("synthetic-throughput-v1\0stable\0".utf8))
        var singles: [CompiledRule] = []
        var sequences: [SequenceRule] = []
        for directory in ["", "sequences"] {
            let url = directory.isEmpty ? root : root.appendingPathComponent(directory)
            let files = try FileManager.default.contentsOfDirectory(at: url, includingPropertiesForKeys: nil)
                .filter { $0.pathExtension == "json" && $0.lastPathComponent != "manifest.json" }
                .sorted { $0.lastPathComponent < $1.lastPathComponent }
            try #require(!files.isEmpty && files.count <= 20_000)
            for file in files {
                let data = try RuleFileLoadingPolicy.read(file)
                // Unambiguous name + content digest; no generated timestamps.
                hash.update(data: Data((directory + "/" + file.lastPathComponent + "\0").utf8))
                hash.update(data: Data(SHA256.hash(data: data)))
                if directory.isEmpty { singles.append(try JSONDecoder().decode(CompiledRule.self, from: data)) }
                else { sequences.append(try JSONDecoder().decode(SequenceRule.self, from: data)) }
            }
        }
        try #require(Set(singles.map(\.id)).count == singles.count)
        try #require(Set(sequences.map(\.id)).count == sequences.count)
        return Corpus(digest: hash.finalize().map { String(format: "%02x", $0) }.joined(),
                      singles: singles, sequences: sequences)
    }

    private func events(batch: Int, count: Int, unlinkOnly: Bool) -> [Event] {
        let now = Date()
        return (0..<count).map { index in
            let variant = index % 6
            let timestamp = now.addingTimeInterval(Double(index) / 10_000)
            let process = MacCrabCore.ProcessInfo(pid: Int32(4_000 + index), ppid: 1, rpid: Int32(4_000 + index),
                name: "fixture-editor", executable: "/Applications/FixtureEditor.app/Contents/MacOS/FixtureEditor",
                commandLine: "fixture-editor ordinary-notes", args: ["ordinary-notes"],
                workingDirectory: "/private/tmp/fixture-project", userId: 501, userName: "fixture",
                groupId: 20, startTime: now.addingTimeInterval(-5),
                codeSignature: CodeSignatureInfo(signerType: .devId, teamId: "FIXTURE123", isNotarized: true),
                isPlatformBinary: false)
            let id = UUID(uuidString: String(format: "00000000-0000-4000-8000-%012x",
                (unlinkOnly ? 8_192 : 0) + batch * 1_024 + index + 1))!
            if unlinkOnly {
                return Event(id: id, timestamp: timestamp, eventCategory: .file, eventType: .deletion,
                    eventAction: "unlink", process: process,
                    file: FileInfo(path: "/private/tmp/fixture-project/Notes\(index).txt", action: .delete))
            }
            if variant < 4 {
                let actions: [FileAction] = [.create, .open, .write, .close]
                let action = actions[variant]
                var enrichments: [String: String] = [:]
                enrichments[DeferredEventEnrichment.coverageKey] =
                    DeferredEventEnrichment.coverageMarker([.fileContent: .pending])
                return Event(id: id, timestamp: timestamp, eventCategory: .file, eventType: .change,
                    eventAction: action.rawValue, process: process,
                    file: FileInfo(path: "/private/tmp/fixture-project/Notes\(index).txt", action: action),
                    enrichments: enrichments)
            }
            return Event(id: id, timestamp: timestamp, eventCategory: .process,
                         eventType: variant == 4 ? .start : .end,
                         eventAction: variant == 4 ? "exec" : "exit", process: process)
        }
    }

    private func replay(_ events: [Event]) -> [Event] {
        events.filter { $0.eventCategory == .file }.map { event in
            var result = event
            result.enrichments["FileContent"] = "Ordinary project notes and a short meeting agenda."
            // Successful production enrichment removes its coverage entry;
            // this fixture's fileContent component is the only pending one.
            result.enrichments.removeValue(forKey: DeferredEventEnrichment.coverageKey)
            return result
        }
    }

    private func category(_ event: Event) -> String {
        if event.eventCategory == .file { return "file_event" }
        return event.eventType == .end ? "process_termination" : "process_creation"
    }

    private func expectedCounts(singles: [CompiledRule], sequences: [SequenceRule],
                                events: [Event], replays: [Event]) -> (UInt64, UInt64) {
        var singleCount: UInt64 = 0
        var sequenceCount: UInt64 = 0
        let completed = HeavyEnrichmentDependencyMask(components: [.fileContent])
        for (inputs, isReplay) in [(events, false), (replays, true)] {
            for event in inputs {
                let source = category(event)
                for rule in singles where rule.enabled && rule.logsource.category == source {
                    if !isReplay || !HeavyEnrichmentRuleCoverage.dependencyMask(
                        predicates: rule.predicates, conditionTree: rule.conditionTree).intersection(completed).isEmpty {
                        singleCount += 1
                    }
                }
                for rule in sequences where rule.enabled {
                    if rule.steps.contains(where: { step in
                        step.logsourceCategory == source && (!isReplay || !HeavyEnrichmentRuleCoverage.dependencyMask(
                            predicates: step.predicates, conditionTree: step.conditionTree).intersection(completed).isEmpty)
                    }) { sequenceCount += 1 }
                }
            }
        }
        return (singleCount, sequenceCount)
    }

    private func nanoseconds(_ duration: Duration) -> Double {
        Double(duration.components.seconds) * 1e9 + Double(duration.components.attoseconds) / 1e9
    }

    @Test("Fixed fresh batches exercise the complete stable corpus without dropped evaluations")
    func productionCorpus() async throws {
        let root = try ensureRulesCompiled() // Existing bounded, owned Python compilation; not timed.
        let inventory = try corpus(at: root)
        let expectedSingleIDs = Set(inventory.singles.filter { $0.enabled && ($0.status ?? "experimental").lowercased() == "stable" }.map(\.id))
        let expectedSequenceIDs = Set(inventory.sequences.filter { ($0.status ?? "stable").lowercased() == "stable" }.map(\.id))
        try #require(!expectedSingleIDs.isEmpty && !expectedSequenceIDs.isEmpty)
        let telemetryDirectory = FileManager.default.temporaryDirectory.appendingPathComponent("detection-throughput-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: telemetryDirectory, withIntermediateDirectories: false,
                                              attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: telemetryDirectory) }

        // First batch warms code/corpus caches but uses separate engine state.
        // The three measured batches always start with fresh default engines.
        for unlinkOnly in [false, true] {
          for batch in 0..<4 {
            let engine = RuleEngine()
            let sequence = SequenceEngine(lineage: ProcessLineage())
            let singleLoaded = try await engine.loadRules(from: root, enabledStatuses: profile)
            let sequenceLoaded = try await sequence.loadRules(from: root.appendingPathComponent("sequences"), enabledStatuses: profile)
            let actualSingles = await engine.listRules()
            let actualSequences = await sequence.listRules()
            try #require(singleLoaded == inventory.singles.count && actualSingles.count == inventory.singles.count)
            try #require(Set(actualSingles.filter(\.enabled).map(\.id)) == expectedSingleIDs)
            try #require(sequenceLoaded == expectedSequenceIDs.count && Set(actualSequences.map(\.id)) == expectedSequenceIDs)
            let inputs = events(batch: batch, count: batch == 0 ? 16 : batchSize, unlinkOnly: unlinkOnly)
            let replays = replay(inputs)
            try #require(Set(inputs.map(\.id)).count == inputs.count)
            try #require(replays.map(\.id) == inputs.filter { $0.eventCategory == .file }.map(\.id))
            if !unlinkOnly {
                try #require(inputs.filter { $0.eventCategory == .file }.allSatisfy {
                    DeferredEventEnrichment.coverage(in: $0)[.fileContent] == .pending
                })
            }
            try #require(replays.allSatisfy {
                $0.enrichments[DeferredEventEnrichment.coverageKey] == nil &&
                    HeavyEnrichmentRuleCoverage.unresolvedMask(in: $0).isEmpty
            })
            let expected = expectedCounts(singles: actualSingles, sequences: actualSequences, events: inputs, replays: replays)
            var singleNS = 0.0, sequenceNS = 0.0
            var singleInitialNS = 0.0, sequenceInitialNS = 0.0
            var singleReplayNS = 0.0, sequenceReplayNS = 0.0
            var singleMatches = 0, sequenceMatches = 0
            var matchDigest = SHA256()
            let clock = ContinuousClock()
            let start = clock.now
            for (records, isReplay) in [(inputs, false), (replays, true)] {
                for event in records {
                    try Task.checkCancellation()
                    // A bounded cooperative guard, not a performance SLA or a
                    // substitute for the parent process-group deadline.
                    try #require(start.duration(to: clock.now) < .seconds(60))
                    let singleStart = clock.now
                    let single: [RuleMatch]
                    if isReplay { single = await engine.reevaluate(event, forCompleted: [.fileContent]) }
                    else { single = await engine.evaluate(event) }
                    let singleElapsed = nanoseconds(singleStart.duration(to: clock.now))
                    singleNS += singleElapsed
                    if isReplay { singleReplayNS += singleElapsed } else { singleInitialNS += singleElapsed }
                    let sequenceStart = clock.now
                    let temporal: [RuleMatch]
                    if isReplay { temporal = await sequence.reevaluate(event, forCompleted: [.fileContent]) }
                    else { temporal = await sequence.evaluate(event) }
                    let sequenceElapsed = nanoseconds(sequenceStart.duration(to: clock.now))
                    sequenceNS += sequenceElapsed
                    if isReplay { sequenceReplayNS += sequenceElapsed } else { sequenceInitialNS += sequenceElapsed }
                    singleMatches += single.count
                    sequenceMatches += temporal.count
                    // Consume real verdicts without printing IDs, text or paths.
                    for (kind, values) in [("single", single), ("sequence", temporal)] {
                        matchDigest.update(data: Data((kind + ":" + event.id.uuidString + ":\(isReplay)\0").utf8))
                        for id in values.map(\.ruleId).sorted() { matchDigest.update(data: Data((id + "\0").utf8)) }
                    }
                }
            }
            let elapsedNS = nanoseconds(start.duration(to: clock.now))
            try #require(singleNS.isFinite && sequenceNS.isFinite && elapsedNS > 0)
            try #require(await engine.autoDisabledRules.isEmpty)
            // RuleEngine exposes exact counters through its supported snapshot
            // writer, not an in-memory getter. This private write is not timed.
            let telemetry = telemetryDirectory.appendingPathComponent("\(unlinkOnly ? "unlink" : "mixed")-batch-\(batch).json")
            await engine.writeTelemetrySnapshot(to: telemetry.path)
            let snapshot = try #require(RuleEngine.readTelemetrySnapshot(at: telemetry.path))
            let temporalStats = await sequence.statsSnapshot()
            try #require(snapshot.stats.reduce(UInt64(0)) { $0 + $1.evaluationCount } == expected.0)
            try #require(temporalStats.reduce(UInt64(0)) { $0 + $1.evaluationCount } == expected.1)
            try #require(snapshot.stats.reduce(UInt64(0)) { $0 + $1.fireCount } == UInt64(singleMatches))
            try #require(temporalStats.reduce(UInt64(0)) { $0 + $1.fireCount } == UInt64(sequenceMatches))
            let pressure = await sequence.partialPressureDiagnostics()
            let pending = await sequence.pendingStepConservation()
            let weight = await sequence.checkpointWeightDiagnostics()
            let pendingLoss = await sequence.pendingStepsEvictedTotal
            try #require(pressure.classificationConserved && !pressure.countersAtLimit && pending.conservationMaintained)
            try #require(weight.cachedWeight == weight.recomputedWeight && weight.maximumWeight == 7_864_320)
            try #require(pressure.globalCountLimit == 13_000)
            if batch > 0 {
                let report: [String: Any] = [
                    "schema": "synthetic-production-detection-v1", "batch": batch, "profile": "stable",
                    "scenario": unlinkOnly ? "unlink" : "mixed",
                    "corpus_sha256": inventory.digest, "loaded_single_rules": singleLoaded,
                    "active_single_rules": expectedSingleIDs.count, "active_sequence_rules": sequenceLoaded,
                    "initial_records": inputs.count, "replay_records": replays.count,
                    "single_evaluations": expected.0, "sequence_evaluations": expected.1,
                    "single_matches": singleMatches, "sequence_matches": sequenceMatches,
                    "single_wall_ns": singleNS, "sequence_wall_ns": sequenceNS,
                    "single_initial_wall_ns": singleInitialNS, "sequence_initial_wall_ns": sequenceInitialNS,
                    "single_replay_wall_ns": singleReplayNS, "sequence_replay_wall_ns": sequenceReplayNS,
                    "loop_wall_ns_including_oracle": elapsedNS,
                    "evaluation_pairs_per_second": Double(inputs.count + replays.count) * 1e9 / (singleNS + sequenceNS),
                    "match_digest": matchDigest.finalize().map { String(format: "%02x", $0) }.joined(),
                    "partials": weight.partialCount, "pending": weight.pendingCount,
                    "semantic_weight_bytes": weight.cachedWeight, "partial_count_shed": pressure.globalCountShedTotal,
                    "partial_weight_shed": pressure.semanticWeightShedTotal, "pending_shed": pendingLoss,
                    "auto_disabled_rules": snapshot.autoDisabledRuleIds.count,
                ]
                let data = try JSONSerialization.data(withJSONObject: report, options: [.sortedKeys])
                print("BENCH_PRODUCTION_DETECTION " + String(decoding: data, as: UTF8.self))
            }
          }
        }
        let finalInventory = try corpus(at: root)
        #expect(finalInventory.digest == inventory.digest, "Corpus changed during evaluation")
    }
}
