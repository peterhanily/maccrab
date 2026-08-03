// ProcessTreeAnalyzerTests.swift
//
// v1.21.4 (deep-audit corr-campaign-anomaly) regression coverage for the
// ProcessTreeAnalyzer Markov engine:
//   #7 normalizeName was a no-op — version churn fragmented the model.
//   #6 the 2nd-order (bigram) model was never persisted (and never pruned),
//      so it was silently discarded on every daemon restart.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("ProcessTreeAnalyzer")
struct ProcessTreeAnalyzerTests {

    /// EventLoop promotes an individual process-tree transition into behavior
    /// scoring only below this value. A source guard below pins this test
    /// constant to the production call site so the numerical regressions cannot
    /// quietly become weaker than the shipped admission gate.
    private let eventLoopAdmissionThreshold = -8.0

    private var repositoryRoot: URL {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()   // MacCrabCoreTests
            .deletingLastPathComponent()   // Tests
            .deletingLastPathComponent()   // repo root
    }

    private func tmpModelPath() -> String {
        NSTemporaryDirectory() + "pta_\(UUID().uuidString).json"
    }

    // MARK: - #7 normalizeName version stripping

    @Test("Dotted version variants collapse to one parent (python3.11 / python3.12 → python3)")
    func dottedVersionCollapses() async {
        let path = tmpModelPath()
        defer { try? FileManager.default.removeItem(atPath: path) }
        let analyzer = ProcessTreeAnalyzer(minTransitions: 500, modelPath: path)
        await analyzer.recordTransition(parentName: "/opt/homebrew/bin/python3.11", childName: "curl")
        await analyzer.recordTransition(parentName: "python3.12", childName: "curl")
        let stats = await analyzer.stats()
        #expect(stats.uniqueParents == 1,
                "python3.11 and python3.12 must normalize to a single parent 'python3'")
        #expect(stats.uniqueEdges == 1)
    }

    @Test("Separator-delimited version variants collapse (clang-16 / clang_17 → clang)")
    func separatorVersionCollapses() async {
        let path = tmpModelPath()
        defer { try? FileManager.default.removeItem(atPath: path) }
        let analyzer = ProcessTreeAnalyzer(minTransitions: 500, modelPath: path)
        await analyzer.recordTransition(parentName: "zsh", childName: "clang-16")
        await analyzer.recordTransition(parentName: "zsh", childName: "clang_17")
        let stats = await analyzer.stats()
        #expect(stats.uniqueEdges == 1,
                "clang-16 and clang_17 must normalize to a single child 'clang'")
    }

    @Test("Architecture / hash tokens are NOT over-collapsed (x86_64, sha256 stay distinct)")
    func doesNotOverCollapse() async {
        let path = tmpModelPath()
        defer { try? FileManager.default.removeItem(atPath: path) }
        let analyzer = ProcessTreeAnalyzer(minTransitions: 500, modelPath: path)
        await analyzer.recordTransition(parentName: "zsh", childName: "x86_64")
        await analyzer.recordTransition(parentName: "zsh", childName: "sha256")
        let stats = await analyzer.stats()
        #expect(stats.uniqueEdges == 2,
                "x86_64 (digit before '_') and sha256 (no separator) must stay distinct binaries")
    }

    // MARK: - #6 2nd-order (bigram) persistence

    @Test("Second-order bigram counts are persisted and survive a reload")
    func bigramsPersist() async throws {
        let path = tmpModelPath()
        defer { try? FileManager.default.removeItem(atPath: path) }

        let analyzer = ProcessTreeAnalyzer(minTransitions: 1, modelPath: path)
        // grandparent present → populates the 2nd-order model.
        await analyzer.recordTransition(parentName: "bash", childName: "curl", grandparentName: "sshd")
        await analyzer.recordTransition(parentName: "bash", childName: "curl", grandparentName: "sshd")
        try await analyzer.save()

        // The persisted JSON must carry a non-empty "bigrams" object — pre-fix the
        // PersistedModel had no such field, so the whole 2nd-order model was lost.
        let data = try Data(contentsOf: URL(fileURLWithPath: path))
        let json = try JSONSerialization.jsonObject(with: data) as? [String: Any]
        let bigrams = json?["bigrams"] as? [String: Any]
        #expect(bigrams != nil && !(bigrams?.isEmpty ?? true),
                "saved model must persist 2nd-order (bigram) counts")
        #expect(bigrams?["sshd>bash"] != nil,
                "bigram prefix 'sshd>bash' should be persisted")

        // A fresh analyzer loads the model without losing the 1st-order data.
        let reloaded = ProcessTreeAnalyzer(minTransitions: 1, modelPath: path)
        try await reloaded.load()
        let stats = await reloaded.stats()
        #expect(stats.uniqueEdges >= 1, "first-order transitions must survive a reload")
    }

    @Test("Pre-v1.21.4 model files (no bigrams key) still load and keep 1st-order data")
    func loadsLegacyModelWithoutBigrams() async throws {
        let path = tmpModelPath()
        defer { try? FileManager.default.removeItem(atPath: path) }

        // Hand-write a legacy v1 file with NO "bigrams" key.
        let legacy = """
        {"version":1,"totalTransitions":3,"transitions":{"zsh":{"git":3}}}
        """
        try legacy.data(using: .utf8)!.write(to: URL(fileURLWithPath: path))

        let analyzer = ProcessTreeAnalyzer(minTransitions: 1, modelPath: path)
        try await analyzer.load()
        let stats = await analyzer.stats()
        #expect(stats.transitions == 3, "legacy first-order counts must decode intact")
        #expect(stats.uniqueEdges == 1)
    }

    @Test("First-order first-seen parent crosses EventLoop threshold before learning")
    func firstOrderCrossesEventLoopThresholdBeforeLearning() async {
        let path = tmpModelPath()
        defer { try? FileManager.default.removeItem(atPath: path) }
        let analyzer = ProcessTreeAnalyzer(minTransitions: 10_000, modelPath: path)

        // An unseen parent scores 1 / uniqueParents. Seed enough distinct
        // parents that the pre-observation score is below EventLoop's -8 gate.
        // Keep the numeric token away from the suffix: normalizeName strips
        // separator-delimited trailing versions by design.
        let knownParentCount = 4_096
        for index in 0..<knownParentCount {
            await analyzer.recordTransition(
                parentName: "known-parent-\(index)-stable",
                childName: "known-child"
            )
        }
        await analyzer.activate()

        let firstSeen = await analyzer.recordTransition(
            parentName: "previously-unseen-parent",
            childName: "previously-unseen-child"
        )
        let expectedPreObservationScore = log(1.0 / Double(knownParentCount))
        #expect(abs((firstSeen ?? 0) - expectedPreObservationScore) < 1e-12,
                "first-seen parent must be scored against the prior 4,096-parent model")
        #expect((firstSeen ?? 0) < eventLoopAdmissionThreshold,
                "the regression must exercise EventLoop's production anomaly gate")

        // The first call still learns after scoring. The same 1/1 edge is
        // ordinary on its next observation, proving the test did not disable
        // learning merely to obtain an anomalous score.
        let repeated = await analyzer.recordTransition(
            parentName: "previously-unseen-parent",
            childName: "previously-unseen-child"
        )
        #expect(repeated == 0.0)
    }

    @Test("Second-order rare edge crosses EventLoop threshold before learning")
    func bigramCrossesEventLoopThresholdBeforeLearning() async {
        let path = tmpModelPath()
        defer { try? FileManager.default.removeItem(atPath: path) }
        let analyzer = ProcessTreeAnalyzer(minTransitions: 20_000, modelPath: path)

        let parent = "runtime-parent"
        let dominantChild = "dominant-child"
        let rareChild = "rare-child"
        let targetGrandparent = "target-context"

        // In the target grandparent→parent context the rare edge is 1/4096.
        // A second context makes rareChild common in the first-order model, so
        // the result can only cross -8 if the second-order model is selected.
        for _ in 0..<4_095 {
            await analyzer.recordTransition(
                parentName: parent,
                childName: dominantChild,
                grandparentName: targetGrandparent
            )
        }
        await analyzer.recordTransition(
            parentName: parent,
            childName: rareChild,
            grandparentName: targetGrandparent
        )
        for _ in 0..<4_096 {
            await analyzer.recordTransition(
                parentName: parent,
                childName: rareChild,
                grandparentName: "common-context"
            )
        }
        await analyzer.activate()

        let rareBeforeLearning = await analyzer.recordTransition(
            parentName: parent,
            childName: rareChild,
            grandparentName: targetGrandparent
        )
        let expectedPreObservationScore = log(1.0 / 4_096.0)
        #expect(abs((rareBeforeLearning ?? 0) - expectedPreObservationScore) < 1e-12,
                "bigram must use the pre-observation 1/4096 count")
        #expect((rareBeforeLearning ?? 0) < eventLoopAdmissionThreshold,
                "the second-order regression must cross EventLoop's production gate")

        // After the anomalous observation is learned, its 2/4097 probability
        // rises above the gate. A learn-before-score implementation would have
        // returned this non-alerting value on the first call and failed above.
        let rareAfterLearning = await analyzer.recordTransition(
            parentName: parent,
            childName: rareChild,
            grandparentName: targetGrandparent
        )
        #expect((rareAfterLearning ?? -.infinity) > eventLoopAdmissionThreshold)
    }

    @Test("Process-tree test threshold is pinned to EventLoop production gate")
    func eventLoopThresholdCannotDrift() throws {
        let eventLoop = try String(
            contentsOf: repositoryRoot.appendingPathComponent(
                "Sources/MacCrabAgentKit/EventLoop.swift"
            ),
            encoding: .utf8
        )
        #expect(eventLoop.contains("if logProb < -8.0"))
    }
}
