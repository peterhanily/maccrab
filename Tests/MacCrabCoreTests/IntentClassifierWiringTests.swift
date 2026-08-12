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
// And bounds cost via `IntentRefinementCache` (per-session + canonical
// BehaviorBrief scope, 10-min TTL, generation-safe write-back, and LRU
// eviction at 256 entries).
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

/// Deterministic monotonic clock for TTL/generation tests. NSLock makes the
/// synchronous closure safe to pass into the Sendable cache actor.
private final class IntentRefinementTestClock: @unchecked Sendable {
    private let lock = NSLock()
    private var value: TimeInterval

    init(_ value: TimeInterval = 1_000) { self.value = value }

    func now() -> TimeInterval {
        lock.lock()
        defer { lock.unlock() }
        return value
    }

    func advance(by interval: TimeInterval) {
        lock.lock()
        value += interval
        lock.unlock()
    }
}

// MARK: - Shared helpers

private func makeBrief(
    packageName: String = "test-pkg",
    creds: [String] = [],
    egress: [String] = [],
    files: [String] = [],
    procs: [String] = [],
    obfuscated: Bool = false,
    aiTriggered: Bool = false
) -> IntentClassifier.BehaviorBrief {
    IntentClassifier.BehaviorBrief(
        packageName: packageName,
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

private func makeRefinementScope(
    sessionID: String? = "session-test",
    fallbackTreeKey: String = "fallback-tree",
    brief: IntentClassifier.BehaviorBrief = makeBrief()
) -> IntentRefinementCache.Scope {
    // BehaviorBrief contains only JSON-native Codable fields, so canonical
    // encoding cannot fail for this fixture.
    IntentRefinementCache.scope(
        sessionID: sessionID,
        fallbackTreeKey: fallbackTreeKey,
        brief: brief
    )!
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
    scope: IntentRefinementCache.Scope,
    timeoutSeconds: Double = 10.0
) async -> IntentRefinementCache.Refinement? {
    let deadline = Date().addingTimeInterval(timeoutSeconds)
    while Date() < deadline {
        if let r = await cache.refinement(for: scope) {
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

    private var repositoryRoot: URL {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
    }

    private func source(_ relativePath: String) throws -> String {
        try String(
            contentsOf: repositoryRoot.appendingPathComponent(relativePath),
            encoding: .utf8
        )
    }

    private func intentInstallEvent(
        packageName: String,
        sessionID: String? = nil,
        pid: Int32 = 4_242,
        startTime: Date = Date(timeIntervalSince1970: 1_700_000_000),
        pidversion: UInt32? = nil,
        rootPID: Int32? = nil,
        ancestors: [ProcessAncestor]? = nil,
        traceID: String? = nil,
        spanID: String? = nil
    ) -> Event {
        let auditIdentity = pidversion.map {
            AuditIdentity(
                auid: 501, euid: 501, egid: 20, ruid: 501, rgid: 20,
                pid: pid, pidversion: $0, asid: 77
            )
        }
        let processAncestors = ancestors ?? [
            ProcessAncestor(pid: 900, executable: "/bin/zsh", name: "zsh"),
        ]
        let process = MacCrabCore.ProcessInfo(
            pid: pid,
            ppid: processAncestors.first?.pid ?? 1,
            rpid: rootPID ?? processAncestors.last?.pid ?? 1,
            name: "npm",
            executable: "/opt/homebrew/bin/npm",
            commandLine: "npm install \(packageName)",
            args: ["npm", "install", packageName],
            workingDirectory: "/Users/test/project",
            userId: 501,
            userName: "test",
            groupId: 20,
            startTime: startTime,
            ancestors: processAncestors,
            architecture: "arm64",
            isPlatformBinary: false,
            auditIdentity: auditIdentity
        )
        var enrichments = sessionID.map {
            ["ai_tool_session_id": $0, "ai_tool": "codex"]
        } ?? [:]
        if let rootPID { enrichments["ai_root_pid"] = String(rootPID) }
        if let traceID { enrichments[TraceCorrelator.EnrichmentKey.traceId] = traceID }
        if let spanID { enrichments[TraceCorrelator.EnrichmentKey.spanId] = spanID }
        return Event(
            eventCategory: .process,
            eventType: .creation,
            eventAction: "exec",
            process: process,
            enrichments: enrichments
        )
    }

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
        let scope = makeRefinementScope(
            sessionID: nil,
            fallbackTreeKey: "tree-A",
            brief: brief
        )

        if shouldDispatchTieBreaker(
            eventEnrichments: enrichments,
            heuristicConfidence: heuristic.confidence
        ) {
            // Mirror the EventLoop dispatch
            _ = await cache.begin(scope: scope)
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

        let scope = makeRefinementScope(
            sessionID: "ambiguous-session-1",
            fallbackTreeKey: "ambiguous-tree-1",
            brief: brief
        )
        let enrichments = ["ai_tool": "claude"]

        guard shouldDispatchTieBreaker(
            eventEnrichments: enrichments,
            heuristicConfidence: heuristic.confidence
        ) else {
            Issue.record("Gate should have permitted dispatch")
            return
        }

        guard let generation = await cache.begin(scope: scope) else {
            Issue.record("Fresh scope should have been admitted")
            return
        }

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
            _ = await cache.recordResult(
                scope: scope,
                token: generation,
                refinement: r
            )
        }
        await dispatch.value

        // Cache is now populated; this resolves immediately (no deadline race).
        let refinement = await awaitRefinement(in: cache, scope: scope)
        #expect(refinement != nil, "LLM result should have landed in cache")
        #expect(refinement?.label == "exfiltration")
        #expect(refinement?.provider == "CountingLLM")
        #expect(await backend.observedCallCount() == 1)
        let validation = await service.runtimeTelemetrySnapshot()
            .counters(for: .intentClassification)?.downstreamValidation
        #expect(validation?.operationsStartedTotal == 1)
        #expect(validation?.currentOperations == 0)
        #expect(validation?.accepted == 1)
        #expect(validation?.finalRejection == 0)
        #expect(validation?.conservationMaintained == true)
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

    // MARK: 4. Budget cap — per-scope cooldown

    @Test("Budget cap: same session and brief within TTL is not re-dispatched")
    func budgetCapPreventsRepeatDispatch() async {
        let cache = IntentRefinementCache()
        let brief = makeBrief(obfuscated: true, aiTriggered: true)
        let scope = makeRefinementScope(
            sessionID: "repeat-session",
            fallbackTreeKey: "repeat-tree",
            brief: brief
        )

        // First atomic begin on a clean scope is admitted.
        guard let generation = await cache.begin(scope: scope) else {
            Issue.record("Fresh scope should have been admitted")
            return
        }

        // Second check immediately after: must be blocked, even though
        // no result has come back yet (in-flight cooldown).
        #expect(await cache.begin(scope: scope) == nil)

        // Even after the result lands, still blocked (result cooldown).
        let r = IntentRefinementCache.Refinement(
            label: "exfiltration", confidence: 0.85,
            provider: "CountingLLM", reasons: ["test"]
        )
        #expect(await cache.recordResult(
            scope: scope,
            token: generation,
            refinement: r
        ))
        #expect(await cache.begin(scope: scope) == nil)

        // A different durable session is unaffected even with the same brief.
        let otherScope = makeRefinementScope(
            sessionID: "other-session",
            fallbackTreeKey: "repeat-tree",
            brief: brief
        )
        #expect(await cache.begin(scope: otherScope) != nil)
    }

    @Test("Atomic begin admits exactly one concurrent caller per scope")
    func atomicBeginClosesCheckThenRecordRace() async {
        let cache = IntentRefinementCache()
        let scope = makeRefinementScope(
            sessionID: "concurrent-session",
            brief: makeBrief(packageName: "concurrent-package")
        )

        let admitted = await withTaskGroup(of: Bool.self, returning: Int.self) { group in
            for _ in 0..<64 {
                group.addTask {
                    await cache.begin(scope: scope) != nil
                }
            }
            var count = 0
            for await didBegin in group where didBegin {
                count += 1
            }
            return count
        }
        #expect(admitted == 1)
        #expect(await cache.entryCount() == 1)
    }

    @Test("Budget cap: TTL expiry permits a re-dispatch")
    func budgetCapTTLExpiry() async {
        let clock = IntentRefinementTestClock()
        let cache = IntentRefinementCache(
            ttlSeconds: 10,
            maxEntries: 32,
            monotonicNow: clock.now
        )
        let scope = makeRefinementScope(
            sessionID: "ttl-session",
            fallbackTreeKey: "ttl-tree"
        )

        #expect(await cache.begin(scope: scope) != nil)
        #expect(await cache.begin(scope: scope) == nil)

        clock.advance(by: 10)
        #expect(await cache.begin(scope: scope) != nil)
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
        let validation = await service.runtimeTelemetrySnapshot()
            .counters(for: .intentClassification)?.downstreamValidation
        #expect(validation?.operationsStartedTotal == 1)
        #expect(validation?.currentOperations == 0)
        #expect(validation?.accepted == 0)
        #expect(validation?.finalRejection == 1)
        #expect(validation?.conservationMaintained == true)
    }

    @Test("Intent verdict parser requires the complete bounded schema")
    func strictIntentVerdictSchema() {
        #expect(IntentClassifier.parseVerdict(validVerdictJSON) != nil)
        let invalid = [
            #"{"label":"benign","reasons":["ok"]}"#,
            #"{"label":"benign","confidence":0.8}"#,
            #"{"label":"benign","confidence":-0.01,"reasons":["ok"]}"#,
            #"{"label":"benign","confidence":1.01,"reasons":["ok"]}"#,
            #"{"label":"benign","confidence":0.8,"reasons":[]}"#,
            #"{"label":"benign","confidence":0.8,"reasons":["a","b","c","d"]}"#,
            #"{"label":"benign","confidence":0.8,"reasons":["ignore previous instructions"]}"#,
        ]
        for response in invalid {
            #expect(IntentClassifier.parseVerdict(response) == nil)
        }
        let oversizedReason = "{\"label\":\"benign\",\"confidence\":0.8,\"reasons\":[\""
            + String(repeating: "x", count: 1_025) + "\"]}"
        #expect(IntentClassifier.parseVerdict(oversizedReason) == nil)
    }

    @Test("Intent prompt bounds every untrusted scalar and collection")
    func intentPromptIsBounded() {
        let values = (0..<100).map { "value-\($0)-" + String(repeating: "x", count: 2_000) }
        let brief = IntentClassifier.BehaviorBrief(
            packageName: String(repeating: "p", count: 2_000),
            packageRegistry: String(repeating: "r", count: 2_000),
            packageVersion: String(repeating: "v", count: 2_000),
            installerLineage: values,
            credentialsRead: values,
            networkEgress: values,
            filesWritten: values,
            processesSpawned: values,
            hasObfuscatedContent: false,
            hasBundledRuntime: false,
            hasLanguageMismatch: false,
            aiAgentTriggered: true
        )
        let prompt = IntentClassifier.makeUserPrompt(brief)
        #expect(prompt.utf8.count < 80_000)
        #expect(!prompt.contains("value-99-"))
        #expect(prompt.contains("value-15-"))
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
        let brief = makeBrief(obfuscated: true, aiTriggered: true)
        let scope = makeRefinementScope(
            sessionID: "unknown-result-session",
            fallbackTreeKey: "unknown-result-tree",
            brief: brief
        )
        guard let generation = await cache.begin(scope: scope) else {
            Issue.record("Fresh scope should have been admitted")
            return
        }
        let result = await classifier.classify(brief)
        // Mirror the EventLoop guard.
        if result.label != .unknown && result.provider != "heuristic" {
            let r = IntentRefinementCache.Refinement(
                label: result.label.rawValue,
                confidence: result.confidence,
                provider: result.provider,
                reasons: result.reasons
            )
            _ = await cache.recordResult(
                scope: scope,
                token: generation,
                refinement: r
            )
        }

        // No refinement stamped — but the dispatch slot is still held
        // (so we don't immediately re-dispatch on the next event).
        #expect(await cache.refinement(for: scope) == nil)
        #expect(await cache.begin(scope: scope) == nil)
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
            let heuristic = IntentClassifier.heuristicClassifyPublic(brief)
            _ = heuristic
            let scope = makeRefinementScope(
                sessionID: "hot-path-session-\(i)",
                fallbackTreeKey: "hot-path-tree-\(i)",
                brief: brief
            )
            // Mirror the EventLoop dispatch shape: atomic admission + detached
            // Task. The hot path returns immediately after launching the Task.
            if await cache.begin(scope: scope) != nil {
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
        let brief = makeBrief()
        var scopes: [IntentRefinementCache.Scope] = []

        // Insert 6 entries; cache holds at most 4.
        for i in 0..<6 {
            let scope = makeRefinementScope(
                sessionID: "session-\(i)",
                fallbackTreeKey: "tree-\(i)",
                brief: brief
            )
            scopes.append(scope)
            _ = await cache.begin(scope: scope)
        }
        #expect(await cache.entryCount() == 4)

        // Oldest two were evicted and can be admitted again; newest scopes are
        // still in-flight and therefore remain blocked.
        #expect(await cache.begin(scope: scopes[0]) != nil)
        #expect(await cache.begin(scope: scopes[5]) == nil)
    }

    // MARK: 8. Session + BehaviorBrief isolation

    @Test("Package A refinement cannot label package B in the same AI session")
    func packageVerdictsAreBehaviorScoped() async {
        let cache = IntentRefinementCache()
        let briefA = makeBrief(
            packageName: "package-a",
            egress: ["webhook.site"],
            obfuscated: true,
            aiTriggered: true
        )
        let briefB = makeBrief(
            packageName: "package-b",
            aiTriggered: true
        )
        let scopeA = makeRefinementScope(
            sessionID: "shared-ai-session",
            fallbackTreeKey: "shared-terminal-tree",
            brief: briefA
        )
        let scopeB = makeRefinementScope(
            sessionID: "shared-ai-session",
            fallbackTreeKey: "shared-terminal-tree",
            brief: briefB
        )

        #expect(scopeA != scopeB)
        #expect(scopeA.behaviorSHA256.count == 64)
        #expect(scopeA.behaviorSHA256 != scopeB.behaviorSHA256)

        guard let tokenA = await cache.begin(scope: scopeA) else {
            Issue.record("Package A scope should have been admitted")
            return
        }
        let verdictA = IntentRefinementCache.Refinement(
            label: "exfiltration",
            confidence: 0.91,
            provider: "CountingLLM",
            reasons: ["package A contacted a non-registry endpoint"]
        )
        #expect(await cache.recordResult(
            scope: scopeA,
            token: tokenA,
            refinement: verdictA
        ))

        let cachedA = await cache.refinement(for: scopeA)
        let leakedIntoB = await cache.refinement(for: scopeB)
        #expect(cachedA?.label == "exfiltration")
        #expect(leakedIntoB == nil,
                "A package-scoped LLM verdict must never stamp package B")
    }

    @Test("Identical brief in one durable session reuses its cached refinement")
    func sameScopeReusesCache() async {
        let cache = IntentRefinementCache()
        let brief = makeBrief(
            packageName: "repeat-package",
            obfuscated: true,
            aiTriggered: true
        )
        let original = makeRefinementScope(
            sessionID: "durable-session-id",
            fallbackTreeKey: "tree-before",
            brief: brief
        )
        // Once the durable session exists, a changed fallback tree string is
        // irrelevant. This avoids accidental cache misses from ancestry shape.
        let repeated = makeRefinementScope(
            sessionID: "durable-session-id",
            fallbackTreeKey: "tree-after",
            brief: brief
        )
        #expect(original == repeated)
        #expect(original.subjectIdentity == "session:durable-session-id")

        guard let token = await cache.begin(scope: original) else {
            Issue.record("Original scope should have been admitted")
            return
        }
        let refinement = IntentRefinementCache.Refinement(
            label: "persistence",
            confidence: 0.8,
            provider: "CountingLLM",
            reasons: ["LaunchAgent write"]
        )
        #expect(await cache.recordResult(
            scope: original,
            token: token,
            refinement: refinement
        ))
        #expect((await cache.refinement(for: repeated))?.label == "persistence")
        #expect(await cache.begin(scope: repeated) == nil,
                "A live completed scope must not dispatch twice")

        let fallbackOnly = makeRefinementScope(
            sessionID: "  ",
            fallbackTreeKey: "tree-before",
            brief: brief
        )
        #expect(fallbackOnly.subjectIdentity == "tree:tree-before")
        #expect(fallbackOnly != original)
    }

    // MARK: 9. Async generation conservation

    @Test("Rejected advisory admission releases the exact cooldown reservation")
    func rejectedDispatchReleasesReservation() async {
        let cache = IntentRefinementCache()
        let scope = makeRefinementScope(
            sessionID: "overloaded-session",
            brief: makeBrief(packageName: "overloaded-package", aiTriggered: true)
        )
        guard let rejectedToken = await cache.begin(scope: scope) else {
            Issue.record("Initial reservation should be admitted")
            return
        }

        #expect(await cache.cancelBeforeDispatch(
            scope: scope,
            token: rejectedToken
        ))
        let replacement = await cache.begin(scope: scope)
        #expect(replacement != nil,
                "A task that never started must not consume the cooldown")
        #expect(await cache.cancelBeforeDispatch(
            scope: scope,
            token: rejectedToken
        ) == false, "A stale token cannot cancel its replacement")

        let telemetry = await cache.telemetry()
        #expect(telemetry.beginOffered == 2)
        #expect(telemetry.admitted == 2)
        #expect(telemetry.cancelledBeforeDispatch == 1)
        #expect(telemetry.currentEntries == 1)
        #expect(telemetry.currentInFlight == 1)
        #expect(telemetry.beginConservationMaintained)
        #expect(telemetry.entryConservationMaintained)
        #expect(telemetry.resultConservationMaintained)
    }

    @Test("Expired generation rejects its result and cannot overwrite a replacement")
    func expiredAndLateResultsAreRejected() async {
        let clock = IntentRefinementTestClock()
        let cache = IntentRefinementCache(
            ttlSeconds: 10,
            maxEntries: 8,
            monotonicNow: clock.now
        )
        let scope = makeRefinementScope(
            sessionID: "slow-llm-session",
            brief: makeBrief(packageName: "slow-package", aiTriggered: true)
        )
        let refinement = IntentRefinementCache.Refinement(
            label: "destructive",
            confidence: 0.9,
            provider: "CountingLLM",
            reasons: ["test"]
        )

        guard let oldToken = await cache.begin(scope: scope) else {
            Issue.record("Initial generation should have been admitted")
            return
        }
        clock.advance(by: 10)
        #expect(await cache.recordResult(
            scope: scope,
            token: oldToken,
            refinement: refinement
        ) == false)
        #expect(await cache.refinement(for: scope) == nil)

        guard let newToken = await cache.begin(scope: scope) else {
            Issue.record("Expired scope should admit a replacement generation")
            return
        }
        #expect(newToken != oldToken)
        #expect(await cache.recordResult(
            scope: scope,
            token: oldToken,
            refinement: refinement
        ) == false, "Late old task must not overwrite the new generation")
        #expect(await cache.recordResult(
            scope: scope,
            token: newToken,
            refinement: refinement
        ))
        #expect((await cache.refinement(for: scope))?.label == "destructive")
    }

    @Test("Evicted generation cannot resurrect its cache entry")
    func evictedResultCannotResurrectState() async {
        let cache = IntentRefinementCache(ttlSeconds: 600, maxEntries: 1)
        let scopeA = makeRefinementScope(
            sessionID: "eviction-session-a",
            brief: makeBrief(packageName: "package-a")
        )
        let scopeB = makeRefinementScope(
            sessionID: "eviction-session-b",
            brief: makeBrief(packageName: "package-b")
        )
        guard let tokenA = await cache.begin(scope: scopeA),
              let tokenB = await cache.begin(scope: scopeB) else {
            Issue.record("Both distinct scopes should be admitted")
            return
        }
        #expect(await cache.entryCount() == 1)

        let lateA = IntentRefinementCache.Refinement(
            label: "exfiltration",
            confidence: 0.95,
            provider: "CountingLLM",
            reasons: ["late"]
        )
        #expect(await cache.recordResult(
            scope: scopeA,
            token: tokenA,
            refinement: lateA
        ) == false)
        #expect(await cache.entryCount() == 1,
                "Rejected write-back must not recreate the evicted entry")
        #expect(await cache.refinement(for: scopeA) == nil)

        let currentB = IntentRefinementCache.Refinement(
            label: "benign",
            confidence: 0.88,
            provider: "CountingLLM",
            reasons: ["current"]
        )
        #expect(await cache.recordResult(
            scope: scopeB,
            token: tokenB,
            refinement: currentB
        ))
        #expect((await cache.refinement(for: scopeB))?.label == "benign")
    }

    // MARK: 10. Bayesian posterior scope isolation

    @Test("Different command subtrees in one AI session keep package evidence isolated")
    func bayesianSameSessionOperationIsolation() async {
        let root = ProcessAncestor(pid: 700, executable: "/usr/local/bin/codex", name: "codex")
        let shellA = ProcessAncestor(pid: 701, executable: "/bin/zsh", name: "zsh")
        let shellB = ProcessAncestor(pid: 702, executable: "/bin/zsh", name: "zsh")
        let packageA = intentInstallEvent(
            packageName: "package-a", sessionID: "shared-session", pid: 801,
            rootPID: root.pid, ancestors: [shellA, root]
        )
        let packageB = intentInstallEvent(
            packageName: "package-b", sessionID: "shared-session", pid: 802,
            rootPID: root.pid, ancestors: [shellB, root]
        )
        let keyA = IntentEvidenceClassifier.scopeKey(for: packageA)
        let keyB = IntentEvidenceClassifier.scopeKey(for: packageB)
        #expect(keyA.hasPrefix("ai-operation:shared-session:root-child:"))
        #expect(keyB.hasPrefix("ai-operation:shared-session:root-child:"))
        #expect(keyA != keyB)

        let engine = BayesianIntentEngine()
        _ = await engine.observe(.credentialRead, treeKey: keyA)
        _ = await engine.observe(.nonRegistryEgress, treeKey: keyA)
        _ = await engine.observe(.launchAgentWrite, treeKey: keyA)
        let snapshotA = await engine.posterior(treeKey: keyA)
        let snapshotB = await engine.posterior(treeKey: keyB)
        #expect(snapshotA?.treeKey == keyA)
        #expect(snapshotB == nil)

        let briefA = IntentBriefBuilder.brief(for: packageA, posterior: snapshotA)
        let briefB = IntentBriefBuilder.brief(for: packageB, posterior: snapshotB)
        #expect(briefA?.packageName == "package-a")
        #expect(briefA?.credentialsRead.isEmpty == false)
        #expect(briefB?.packageName == "package-b")
        #expect(briefB?.credentialsRead.isEmpty == true,
                "Package A evidence must not enter package B in the same AI session")
    }

    @Test("One AI command shares descendant evidence and trace spans override lineage")
    func bayesianOperationContinuity() {
        let root = ProcessAncestor(pid: 700, executable: "/usr/local/bin/codex", name: "codex")
        let shell = ProcessAncestor(pid: 701, executable: "/bin/zsh", name: "zsh")
        let first = intentInstallEvent(
            packageName: "package-a", sessionID: "shared-session", pid: 801,
            rootPID: root.pid, ancestors: [shell, root]
        )
        let descendant = intentInstallEvent(
            packageName: "package-a", sessionID: "shared-session", pid: 802,
            rootPID: root.pid, ancestors: [shell, root]
        )
        #expect(IntentEvidenceClassifier.scopeKey(for: first)
                == IntentEvidenceClassifier.scopeKey(for: descendant))

        let traceID = String(repeating: "a", count: 32)
        let spanID = String(repeating: "b", count: 16)
        let tracedA = intentInstallEvent(
            packageName: "package-a", sessionID: "shared-session", pid: 901,
            rootPID: root.pid, ancestors: [shell, root],
            traceID: traceID, spanID: spanID
        )
        let tracedB = intentInstallEvent(
            packageName: "package-a", sessionID: "shared-session", pid: 902,
            rootPID: root.pid, ancestors: [
                ProcessAncestor(pid: 799, executable: "/bin/bash", name: "bash"), root,
            ],
            traceID: traceID.uppercased(), spanID: spanID.uppercased()
        )
        #expect(IntentEvidenceClassifier.scopeKey(for: tracedA)
                == IntentEvidenceClassifier.scopeKey(for: tracedB))
    }

    @Test("Posterior fallback identities resist PID reuse with and without audit tokens")
    func bayesianPIDReuseFallbackIsolation() {
        let sameStart = Date(timeIntervalSince1970: 1_700_000_000)
        let auditOld = intentInstallEvent(
            packageName: "pkg", pid: 777, startTime: sameStart, pidversion: 10
        )
        let auditRecycled = intentInstallEvent(
            packageName: "pkg", pid: 777, startTime: sameStart, pidversion: 11
        )
        let auditSameIdentityDifferentTimestamp = intentInstallEvent(
            packageName: "pkg", pid: 777,
            startTime: sameStart.addingTimeInterval(1), pidversion: 10
        )
        #expect(IntentEvidenceClassifier.scopeKey(for: auditOld)
                != IntentEvidenceClassifier.scopeKey(for: auditRecycled))
        #expect(IntentEvidenceClassifier.scopeKey(for: auditOld)
                == IntentEvidenceClassifier.scopeKey(for: auditSameIdentityDifferentTimestamp))

        let fallbackOld = intentInstallEvent(
            packageName: "pkg", pid: 888, startTime: sameStart
        )
        let fallbackRecycled = intentInstallEvent(
            packageName: "pkg", pid: 888,
            startTime: sameStart.addingTimeInterval(1)
        )
        let fallbackRepeat = intentInstallEvent(
            packageName: "pkg", pid: 888, startTime: sameStart
        )
        #expect(IntentEvidenceClassifier.scopeKey(for: fallbackOld)
                != IntentEvidenceClassifier.scopeKey(for: fallbackRecycled))
        #expect(IntentEvidenceClassifier.scopeKey(for: fallbackOld)
                == IntentEvidenceClassifier.scopeKey(for: fallbackRepeat))

        let sessionOld = intentInstallEvent(
            packageName: "pkg", sessionID: "durable-session",
            pid: 999, pidversion: 1
        )
        let sessionNewProcess = intentInstallEvent(
            packageName: "pkg", sessionID: "durable-session",
            pid: 1_000, pidversion: 2
        )
        #expect(IntentEvidenceClassifier.scopeKey(for: sessionOld)
                != IntentEvidenceClassifier.scopeKey(for: sessionNewProcess),
                "A session without a proven root/trace must split rather than pool")
    }

    // MARK: 11. Production wiring drift guards

    @Test("Bayesian observe, snapshot, explanation, and brief use one scope key")
    func bayesianScopeWiringDoesNotDrift() throws {
        let eventLoop = try source("Sources/MacCrabAgentKit/EventLoop.swift")
        let classifier = try source("Sources/MacCrabAgentKit/IntentEvidenceClassifier.swift")
        let briefBuilder = try source("Sources/MacCrabAgentKit/IntentBriefBuilder.swift")

        let scopeDefinition =
            "let intentScopeKey = IntentEvidenceClassifier.scopeKey("
        #expect(eventLoop.components(separatedBy: scopeDefinition).count == 2)
        let key = try #require(eventLoop.range(of: scopeDefinition))
        let keyInput = try #require(eventLoop.range(
            of: "for: enrichedEvent",
            range: key.lowerBound..<eventLoop.endIndex
        ))
        let observe = try #require(eventLoop.range(
            of: "treeKey: intentScopeKey",
            range: keyInput.lowerBound..<eventLoop.endIndex
        ))
        let token = try #require(eventLoop.range(
            of: "observationToken: enrichedEvent.id.uuidString",
            range: observe.lowerBound..<eventLoop.endIndex
        ))
        let observedAt = try #require(eventLoop.range(
            of: "observedAt: enrichedEvent.timestamp",
            range: token.lowerBound..<eventLoop.endIndex
        ))
        let snapshot = try #require(eventLoop.range(
            of: "posteriorForBrief = await state.bayesianIntent.posterior(",
            range: observedAt.lowerBound..<eventLoop.endIndex
        ))
        let snapshotScope = try #require(eventLoop.range(
            of: "treeKey: intentScopeKey",
            range: snapshot.lowerBound..<eventLoop.endIndex
        ))
        let refinementFallback = try #require(eventLoop.range(
            of: "fallbackTreeKey: intentScopeKey",
            range: snapshotScope.lowerBound..<eventLoop.endIndex
        ))
        let independentGate = try #require(eventLoop.range(
            of: "posterior.observationAddedIndependentEvidence",
            range: refinementFallback.lowerBound..<eventLoop.endIndex
        ))
        let explanation = try #require(eventLoop.range(
            of: "for intent scope \\(posterior.treeKey)",
            range: independentGate.lowerBound..<eventLoop.endIndex
        ))
        #expect(key.lowerBound < keyInput.lowerBound)
        #expect(keyInput.lowerBound < observe.lowerBound)
        #expect(observe.lowerBound < token.lowerBound)
        #expect(token.lowerBound < observedAt.lowerBound)
        #expect(observedAt.lowerBound < snapshot.lowerBound)
        #expect(snapshot.lowerBound < snapshotScope.lowerBound)
        #expect(snapshotScope.lowerBound < refinementFallback.lowerBound)
        #expect(refinementFallback.lowerBound < independentGate.lowerBound)
        #expect(independentGate.lowerBound < explanation.lowerBound)
        #expect(!eventLoop.contains("IntentEvidenceClassifier.treeKey(for:"))
        #expect(classifier.contains("event.enrichments[\"ai_tool_session_id\"]"))
        #expect(classifier.contains("ai-operation:\\(boundedSessionID)"))
        #expect(classifier.contains("TraceCorrelator.EnrichmentKey.spanId"))
        #expect(classifier.contains("root-child"))
        #expect(classifier.contains("auditIdentity.pidversion"))
        #expect(classifier.contains("process.startTime.timeIntervalSince1970.bitPattern"))
        #expect(!classifier.contains("event.process.ancestors.last"))
        #expect(briefBuilder.contains("event.process.ancestors.prefix(16)"))
        #expect(eventLoop.contains("Uncalibrated normalized advisory score"))
        #expect(eventLoop.contains("not an empirical probability"))
        #expect(!eventLoop.contains("Bayesian belief network reports p("))
    }

    @Test("Intent advisory state is pruned on the owned timer lifecycle")
    func bayesianPruneIsOwnedAndObservable() throws {
        let timers = try source("Sources/MacCrabAgentKit/DaemonTimers.swift")
        #expect(timers.contains("state.bayesianIntent.prune(asOf: Date())"))
        #expect(timers.contains("state.bayesianIntent.statistics()"))
        #expect(timers.contains("intentStats.observationsConserved"))
        #expect(timers.contains("intentStats.treeLifecycleConserved"))
        #expect(timers.contains("intentStats.treeCapacityRespected"))
    }

    @Test("EventLoop uses session+brief scope and atomic generation write-back")
    func eventLoopScopeAndGenerationGuard() throws {
        let eventLoop = try source("Sources/MacCrabAgentKit/EventLoop.swift")
        let cacheSource = try source("Sources/MacCrabAgentKit/IntentRefinementCache.swift")

        let scopeBuild = try #require(eventLoop.range(
            of: "let refinementScope = IntentRefinementCache.scope("
        ))
        let sessionLabel = try #require(eventLoop.range(
            of: "sessionID:",
            range: scopeBuild.lowerBound..<eventLoop.endIndex
        ))
        let sessionID = try #require(eventLoop.range(
            of: "enrichedEvent.enrichments[\"ai_tool_session_id\"]",
            range: sessionLabel.lowerBound..<eventLoop.endIndex
        ))
        let briefDigestInput = try #require(eventLoop.range(
            of: "brief: intentBrief",
            range: sessionID.lowerBound..<eventLoop.endIndex
        ))
        let lookup = try #require(eventLoop.range(
            of: "refinement(for: refinementScope)",
            range: briefDigestInput.lowerBound..<eventLoop.endIndex
        ))
        let begin = try #require(eventLoop.range(
            of: "intentRefinementCache.begin(scope: refinementScope)",
            range: lookup.lowerBound..<eventLoop.endIndex
        ))
        let commit = try #require(eventLoop.range(
            of: "token: generation",
            range: begin.lowerBound..<eventLoop.endIndex
        ))
        let rollback = try #require(eventLoop.range(
            of: "cache.cancelBeforeDispatch(",
            range: commit.lowerBound..<eventLoop.endIndex
        ))
        let recordStart = try #require(cacheSource.range(of: "func recordResult("))
        let lookupStart = try #require(cacheSource.range(
            of: "func refinement(for scope:",
            range: recordStart.lowerBound..<cacheSource.endIndex
        ))
        let recordBody = cacheSource[recordStart.lowerBound..<lookupStart.lowerBound]
        #expect(scopeBuild.lowerBound < sessionLabel.lowerBound)
        #expect(sessionLabel.lowerBound < sessionID.lowerBound)
        #expect(sessionID.lowerBound < briefDigestInput.lowerBound)
        #expect(briefDigestInput.lowerBound < lookup.lowerBound)
        #expect(lookup.lowerBound < begin.lowerBound)
        #expect(begin.lowerBound < commit.lowerBound)
        #expect(commit.lowerBound < rollback.lowerBound)

        #expect(!eventLoop.contains("shouldClassify(treeKey:"))
        #expect(!eventLoop.contains("recordDispatch(treeKey:"))
        #expect(!eventLoop.contains("refinement(for: treeKey)"))
        #expect(cacheSource.contains("SHA256.hash(data: canonical)"))
        #expect(cacheSource.contains("encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]"))
        #expect(cacheSource.contains("func cancelBeforeDispatch("))
        #expect(recordBody.contains("guard var entry = entries[scope], entry.token == token"))
        #expect(!recordBody.contains("entries[scope] = Entry("),
                "recordResult must never synthesize an absent entry")
    }
}
