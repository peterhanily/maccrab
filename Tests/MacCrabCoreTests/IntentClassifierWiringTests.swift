// IntentClassifierWiringTests.swift
// MacCrabCoreTests
//
// v1.12.6 (wire-the-orphans Wave 3A) — verifies the EventLoop wiring of
// the previously-orphaned LLM-aware `IntentClassifier.classify(_:)`
// path. The Wave 3A audit observed that
// `DaemonState.intentClassifier` was constructed in DaemonSetup but
// had zero call sites in production code — the EventLoop hot path
// only invoked the static heuristic. Wave 3A wires the instance method
// behind two gates:
//
//   1. AI-attribution: only fire for `ai_tool` / `agent_tool` /
//      `ai_tool_child=true` enrichments.
//   2. Low heuristic confidence: only fire when the heuristic verdict
//      is < 0.7. Confident heuristic verdicts skip the LLM entirely.
//
// And bounds cost via `IntentRefinementCache` (per-tree 10-min TTL +
// LRU eviction at 256 entries).
//
// The tests below pin the wiring behaviour directly against the
// `IntentClassifier` actor + `IntentRefinementCache`, avoiding the
// full EventLoop / DaemonState fixture — DaemonState construction
// needs the entire production object graph and isn't practical to
// stand up in a unit test.

import Foundation
import Testing
@testable import MacCrabCore
@testable import MacCrabAgentKit

// MARK: - Mock backend that counts invocations

/// Counts LLM dispatches. Returns deterministic JSON so the
/// IntentClassifier's verdict parser produces a known verdict.
/// Optional `delayNs` simulates slow LLM round-trips for the
/// "doesn't block hot path" test.
private actor CountingBackend: LLMBackend {
    let providerName: String = "CountingLLM"
    private(set) var callCount: Int = 0
    private let cannedJSON: String
    private let delayNs: UInt64

    init(cannedJSON: String, delayNs: UInt64 = 0) {
        self.cannedJSON = cannedJSON
        self.delayNs = delayNs
    }

    func isAvailable() async -> Bool { true }

    func complete(
        systemPrompt: String,
        userPrompt: String,
        maxTokens: Int,
        temperature: Double
    ) async -> String? {
        callCount += 1
        if delayNs > 0 {
            try? await Task.sleep(nanoseconds: delayNs)
        }
        return cannedJSON
    }

    func observedCallCount() async -> Int { callCount }
}

/// A backend that always fails (returns nil) — exercises the
/// circuit-breaker / fall-through-to-heuristic path.
private actor FailingBackend: LLMBackend {
    let providerName: String = "FailingLLM"
    private(set) var callCount: Int = 0

    func isAvailable() async -> Bool { true }

    func complete(
        systemPrompt: String, userPrompt: String,
        maxTokens: Int, temperature: Double
    ) async -> String? {
        callCount += 1
        return nil
    }

    func observedCallCount() async -> Int { callCount }
}

// MARK: - Shared helpers

private func makeBrief(
    creds: [String] = [],
    egress: [String] = [],
    files: [String] = [],
    procs: [String] = [],
    obfuscated: Bool = false,
    aiTriggered: Bool = false
) -> IntentClassifier.BehaviorBrief {
    IntentClassifier.BehaviorBrief(
        packageName: "test-pkg",
        packageRegistry: "npm",
        packageVersion: "1.0.0",
        installerLineage: ["npm", "node"],
        credentialsRead: creds,
        networkEgress: egress,
        filesWritten: files,
        processesSpawned: procs,
        hasObfuscatedContent: obfuscated,
        hasBundledRuntime: false,
        hasLanguageMismatch: false,
        aiAgentTriggered: aiTriggered
    )
}

private let validVerdictJSON = """
{"label": "exfiltration", "confidence": 0.83, "reasons": ["egress to webhook.site", "obfuscated install script", "no registry contact"]}
"""

/// Mirror of the gating logic in EventLoop.swift so we can pin
/// "would this event have triggered an LLM dispatch?" without
/// standing up the full DaemonState. EventLoop's logic must stay in
/// lock-step with this helper.
@Sendable private func shouldDispatchTieBreaker(
    eventEnrichments: [String: String],
    heuristicConfidence: Double
) -> Bool {
    let isAI = eventEnrichments["ai_tool"] != nil
        || eventEnrichments["agent_tool"] != nil
        || eventEnrichments["ai_tool_child"] == "true"
    return isAI && heuristicConfidence < 0.7
}

/// Awaits a refinement landing in the cache, up to `timeoutSeconds`
/// total wall-clock. Returns nil on timeout.
private func awaitRefinement(
    in cache: IntentRefinementCache,
    treeKey: String,
    timeoutSeconds: Double = 10.0
) async -> IntentRefinementCache.Refinement? {
    let deadline = Date().addingTimeInterval(timeoutSeconds)
    while Date() < deadline {
        if let r = await cache.refinement(for: treeKey) {
            return r
        }
        // 50ms poll interval — fast enough to catch a sub-second LLM
        // round-trip without burning CPU.
        try? await Task.sleep(nanoseconds: 50_000_000)
    }
    return nil
}

// MARK: - Suite

@Suite("v1.12.6: IntentClassifier wiring (Wave 3A)")
struct IntentClassifierWiringTests {

    // MARK: 1. Heuristic-only path for non-AI events

    @Test("Heuristic path runs by default for non-AI events — no LLM call")
    func heuristicOnlyForNonAI() async {
        let backend = CountingBackend(cannedJSON: validVerdictJSON)
        let service = LLMService(backend: backend, config: LLMConfig())
        let classifier = IntentClassifier(llmService: service)
        let cache = IntentRefinementCache()

        // No ai_tool / agent_tool / ai_tool_child enrichments → gate fails
        let enrichments: [String: String] = [:]
        let brief = makeBrief()
        let heuristic = IntentClassifier.heuristicClassifyPublic(brief)

        if shouldDispatchTieBreaker(
            eventEnrichments: enrichments,
            heuristicConfidence: heuristic.confidence
        ) {
            // Mirror the EventLoop dispatch
            await cache.recordDispatch(treeKey: "tree-A")
            _ = await classifier.classify(brief)
        }

        // The classifier was not dispatched; the heuristic stamp is
        // what would land on the event.
        #expect(await backend.observedCallCount() == 0)
        #expect(heuristic.provider == "heuristic")
        #expect(heuristic.label == .benign)
    }

    // MARK: 2. LLM tie-breaker fires for AI + low-confidence

    @Test("LLM tie-breaker fires once for AI install with low heuristic confidence")
    func tieBreakerFiresOnLowConfidence() async {
        let backend = CountingBackend(cannedJSON: validVerdictJSON)
        let service = LLMService(backend: backend, config: LLMConfig())
        let classifier = IntentClassifier(llmService: service)
        let cache = IntentRefinementCache()

        // A "thin" brief — no malicious signals — produces a heuristic
        // .benign result with confidence 0.8 which would SKIP the LLM.
        // We need an ambiguous brief that scores 0.3 (unknown fallback).
        // Setting hasObfuscatedContent=true gives exfiltration +1 +
        // persistence +1 → top score 1 → falls below the >=3
        // threshold → .unknown @ 0.3 confidence.
        let brief = makeBrief(obfuscated: true, aiTriggered: true)
        let heuristic = IntentClassifier.heuristicClassifyPublic(brief)
        #expect(heuristic.confidence < 0.7,
                "Heuristic should be ambiguous on obfuscation-only brief; got \(heuristic.confidence)")

        let treeKey = "ambiguous-tree-1"
        let enrichments = ["ai_tool": "claude"]

        guard shouldDispatchTieBreaker(
            eventEnrichments: enrichments,
            heuristicConfidence: heuristic.confidence
        ) else {
            Issue.record("Gate should have permitted dispatch")
            return
        }

        let shouldGo = await cache.shouldClassify(treeKey: treeKey)
        #expect(shouldGo == true)
        await cache.recordDispatch(treeKey: treeKey)

        // Dispatch in a detached Task, matching the EventLoop pattern — but
        // CAPTURE the handle and await it deterministically (`.value`) instead
        // of racing a wall-clock poll deadline. Under full-suite parallel load
        // the .utility-priority task can be CPU-starved past awaitRefinement's
        // 10s timeout, which flaked this test in the default (parallel) gate
        // while passing serial/isolated. Awaiting the handle removes the race.
        let dispatch = Task.detached(priority: .utility) { @Sendable in
            let result = await classifier.classify(brief)
            guard result.label != .unknown, result.provider != "heuristic" else {
                return
            }
            let r = IntentRefinementCache.Refinement(
                label: result.label.rawValue,
                confidence: result.confidence,
                provider: result.provider,
                reasons: result.reasons
            )
            await cache.recordResult(treeKey: treeKey, refinement: r)
        }
        await dispatch.value

        // Cache is now populated; this resolves immediately (no deadline race).
        let refinement = await awaitRefinement(in: cache, treeKey: treeKey)
        #expect(refinement != nil, "LLM result should have landed in cache")
        #expect(refinement?.label == "exfiltration")
        #expect(refinement?.provider == "CountingLLM")
        #expect(await backend.observedCallCount() == 1)
    }

    // MARK: 3. High-confidence heuristic skips LLM

    @Test("LLM tie-breaker skipped when heuristic confidence >= 0.7")
    func tieBreakerSkippedWhenHeuristicConfident() async {
        let backend = CountingBackend(cannedJSON: validVerdictJSON)
        let service = LLMService(backend: backend, config: LLMConfig())
        _ = IntentClassifier(llmService: service)
        let cache = IntentRefinementCache()

        // Empty brief → heuristic returns .benign with confidence 0.8.
        // Gate should skip the LLM.
        let brief = makeBrief(aiTriggered: true)
        let heuristic = IntentClassifier.heuristicClassifyPublic(brief)
        #expect(heuristic.confidence >= 0.7,
                "Empty brief heuristic should be confident; got \(heuristic.confidence)")

        let enrichments = ["ai_tool": "claude"]
        let gatePassed = shouldDispatchTieBreaker(
            eventEnrichments: enrichments,
            heuristicConfidence: heuristic.confidence
        )
        #expect(gatePassed == false)

        // The cache and backend remain untouched.
        #expect(await cache.entryCount() == 0)
        #expect(await backend.observedCallCount() == 0)
    }

    // MARK: 4. Budget cap — per-tree cooldown

    @Test("Budget cap: same tree key within TTL is not re-dispatched")
    func budgetCapPreventsRepeatDispatch() async {
        let cache = IntentRefinementCache()
        let treeKey = "repeat-tree"

        // First check: clean cache, dispatch allowed.
        #expect(await cache.shouldClassify(treeKey: treeKey) == true)
        await cache.recordDispatch(treeKey: treeKey)

        // Second check immediately after: must be blocked, even though
        // no result has come back yet (in-flight cooldown).
        #expect(await cache.shouldClassify(treeKey: treeKey) == false)

        // Even after the result lands, still blocked (result cooldown).
        let r = IntentRefinementCache.Refinement(
            label: "exfiltration", confidence: 0.85,
            provider: "CountingLLM", reasons: ["test"]
        )
        await cache.recordResult(treeKey: treeKey, refinement: r)
        #expect(await cache.shouldClassify(treeKey: treeKey) == false)

        // Different tree key is unaffected.
        #expect(await cache.shouldClassify(treeKey: "other-tree") == true)
    }

    @Test("Budget cap: TTL expiry permits a re-dispatch")
    func budgetCapTTLExpiry() async {
        // 50ms TTL so the test completes quickly.
        let cache = IntentRefinementCache(ttlSeconds: 0.05, maxEntries: 32)
        let treeKey = "ttl-tree"

        #expect(await cache.shouldClassify(treeKey: treeKey) == true)
        await cache.recordDispatch(treeKey: treeKey)
        #expect(await cache.shouldClassify(treeKey: treeKey) == false)

        // Wait past the TTL.
        try? await Task.sleep(nanoseconds: 100_000_000) // 100ms
        #expect(await cache.shouldClassify(treeKey: treeKey) == true)
    }

    // MARK: 5. Circuit breaker / failure → heuristic fallback

    @Test("LLM failure → heuristic verdict retained, no error propagated")
    func llmFailureFallsBackToHeuristic() async {
        let backend = FailingBackend()
        let service = LLMService(backend: backend, config: LLMConfig())
        let classifier = IntentClassifier(llmService: service)

        let brief = makeBrief(creds: ["~/.aws/credentials"], aiTriggered: true)
        let heuristic = IntentClassifier.heuristicClassifyPublic(brief)
        // Heuristic confidently labels this as credentialHarvest.
        #expect(heuristic.label == .credentialHarvest)

        // Even though the LLM is asked, it returns nil → the
        // IntentClassifier falls back to the heuristic internally.
        // (Useful as a belt-and-braces check — verifies the classifier
        // never crashes on a nil LLM response.)
        let result = await classifier.classify(brief)
        #expect(result.label == .credentialHarvest)
        #expect(result.provider == "heuristic")
        #expect(await backend.observedCallCount() == 1)
    }

    @Test("LLM returns .unknown → cache stays empty, no refinement stamped")
    func llmUnknownDoesNotPoisonCache() async {
        // LLM returns parseable JSON with .unknown label.
        let unknownJSON = """
        {"label": "unknown", "confidence": 0.3, "reasons": ["insufficient evidence"]}
        """
        let backend = CountingBackend(cannedJSON: unknownJSON)
        let service = LLMService(backend: backend, config: LLMConfig())
        let classifier = IntentClassifier(llmService: service)
        let cache = IntentRefinementCache()
        let treeKey = "unknown-result-tree"

        await cache.recordDispatch(treeKey: treeKey)
        let brief = makeBrief(obfuscated: true, aiTriggered: true)
        let result = await classifier.classify(brief)
        // Mirror the EventLoop guard.
        if result.label != .unknown && result.provider != "heuristic" {
            let r = IntentRefinementCache.Refinement(
                label: result.label.rawValue,
                confidence: result.confidence,
                provider: result.provider,
                reasons: result.reasons
            )
            await cache.recordResult(treeKey: treeKey, refinement: r)
        }

        // No refinement stamped — but the dispatch slot is still held
        // (so we don't immediately re-dispatch on the next event).
        #expect(await cache.refinement(for: treeKey) == nil)
        #expect(await cache.shouldClassify(treeKey: treeKey) == false)
    }

    // MARK: 6. Hot-path throughput — detached LLM doesn't block

    @Test("Detached LLM dispatch does not block the synchronous classification path")
    func detachedDispatchDoesNotBlockHotPath() async {
        // 500ms simulated LLM latency. If the hot path blocked, the
        // 100-iteration loop below would take >50s. Threshold is 5s
        // (10× headroom for slow CI).
        let backend = CountingBackend(cannedJSON: validVerdictJSON, delayNs: 500_000_000)
        let service = LLMService(backend: backend, config: LLMConfig())
        let classifier = IntentClassifier(llmService: service)
        let cache = IntentRefinementCache()

        let brief = makeBrief(obfuscated: true, aiTriggered: true)
        // Heuristic runs synchronously; dispatch is detached. Measure
        // wall-clock time for the synchronous portion of N "events".
        let start = Date()
        for i in 0..<100 {
            let treeKey = "hot-path-tree-\(i)"
            let heuristic = IntentClassifier.heuristicClassifyPublic(brief)
            _ = heuristic
            // Mirror the EventLoop dispatch shape: cache-gate +
            // record + detached Task that calls the LLM. The hot
            // path returns immediately after launching the Task.
            if await cache.shouldClassify(treeKey: treeKey) {
                await cache.recordDispatch(treeKey: treeKey)
                Task.detached(priority: .utility) { @Sendable in
                    _ = await classifier.classify(brief)
                }
            }
        }
        let elapsed = Date().timeIntervalSince(start)

        // The synchronous loop must complete promptly. 5 seconds is
        // ~10× CI slack on a workload that should finish in <100ms.
        #expect(elapsed < 5.0, "Hot path blocked? Elapsed=\(elapsed)s for 100 events")
    }

    // MARK: 7. LRU eviction bounds memory

    @Test("Refinement cache evicts oldest entries when over capacity")
    func cacheLRUEviction() async {
        let cache = IntentRefinementCache(ttlSeconds: 600, maxEntries: 4)

        // Insert 6 entries; cache holds at most 4.
        for i in 0..<6 {
            await cache.recordDispatch(treeKey: "tree-\(i)")
        }
        #expect(await cache.entryCount() == 4)

        // Oldest two should be evicted; newest four retained.
        #expect(await cache.shouldClassify(treeKey: "tree-0") == true)
        #expect(await cache.shouldClassify(treeKey: "tree-1") == true)
    }
}
