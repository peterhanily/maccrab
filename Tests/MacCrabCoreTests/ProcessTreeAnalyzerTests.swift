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
}
