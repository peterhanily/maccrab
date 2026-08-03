// LLMServiceEnvelopeTests.swift
// MacCrabCoreTests
//
// Drives LLMService.query() through its safety envelope with a scriptable
// backend: the circuit breaker (3 nils → open, skip backend), the 50KB
// response discard, sanitize-gating (cloud sanitizes, loopback Ollama does
// not — the RC27 leak boundary), and cache write-through. minInterval is
// injected as 0 so the 5s production rate limiter doesn't stall the test.

import Testing
import Foundation
@testable import MacCrabCore

/// Scriptable LLM backend: returns queued responses and records what it saw.
actor RecordingBackend: LLMBackend {
    let providerName: String
    private var responses: [String?]
    private(set) var calls = 0
    private(set) var lastUserPrompt: String?

    init(providerName: String = "Recording", responses: [String?]) {
        self.providerName = providerName
        self.responses = responses
    }

    func isAvailable() async -> Bool { true }

    func complete(systemPrompt: String, userPrompt: String,
                  maxTokens: Int, temperature: Double) async -> String? {
        calls += 1
        lastUserPrompt = userPrompt
        return responses.isEmpty ? nil : responses.removeFirst()
    }
}

/// Manual monotonic clock for the concurrent rate-limit regression. Sleeping
/// tasks remain suspended until the test advances time, so the test can wake a
/// burst on the same instant without relying on wall-clock scheduling.
private actor ManualLLMRateLimitClock {
    private struct Sleeper {
        let deadline: TimeInterval
        let continuation: CheckedContinuation<Void, Error>
    }

    private var currentTime: TimeInterval = 0
    private var sleepers: [Sleeper] = []

    func now() -> TimeInterval { currentTime }

    func sleep(for interval: TimeInterval) async throws {
        try Task.checkCancellation()
        try await withCheckedThrowingContinuation {
            (continuation: CheckedContinuation<Void, Error>) in
            let deadline = currentTime + max(0, interval)
            if deadline <= currentTime {
                continuation.resume()
            } else {
                sleepers.append(Sleeper(deadline: deadline, continuation: continuation))
            }
        }
    }

    func advance(by interval: TimeInterval) {
        currentTime += interval
        let ready = sleepers.filter { $0.deadline <= currentTime }
        sleepers.removeAll { $0.deadline <= currentTime }

        for sleeper in ready {
            sleeper.continuation.resume()
        }
    }

    var sleeperCount: Int { sleepers.count }
}

private actor RateLimitRecordingBackend: LLMBackend {
    let providerName = "RateLimitRecording"
    private let now: @Sendable () async -> TimeInterval
    private var invocations: [(prompt: String, time: TimeInterval)] = []

    init(now: @escaping @Sendable () async -> TimeInterval) {
        self.now = now
    }

    func isAvailable() async -> Bool { true }

    func complete(systemPrompt: String, userPrompt: String,
                  maxTokens: Int, temperature: Double) async -> String? {
        invocations.append((prompt: userPrompt, time: await now()))
        return "ok"
    }

    func snapshot() -> [(prompt: String, time: TimeInterval)] {
        invocations
    }
}

@Suite("LLMService safety envelope")
struct LLMServiceEnvelopeTests {

    private func cloudConfig() -> LLMConfig {
        var c = LLMConfig(); c.provider = .claude; c.sanitizeForCloud = true; return c
    }

    private func eventually(
        maxYields: Int = 10_000,
        _ predicate: @escaping @Sendable () async -> Bool
    ) async -> Bool {
        for _ in 0..<maxYields {
            if await predicate() { return true }
            await Task.yield()
        }
        return await predicate()
    }

    @Test("Circuit breaker opens after 3 failures; 4th query skips the backend")
    func circuitBreaker() async {
        let backend = RecordingBackend(responses: [nil, nil, nil, "unused"])
        let service = LLMService(backend: backend, config: cloudConfig(), minInterval: 0)
        for _ in 0..<3 {
            #expect(await service.query(systemPrompt: "s", userPrompt: "u", useCache: false) == nil)
        }
        // Breaker is open — returns nil WITHOUT touching the backend.
        #expect(await service.query(systemPrompt: "s", userPrompt: "u", useCache: false) == nil)
        #expect(await backend.calls == 3)
        #expect(await service.healthSnapshot().circuitOpen == true)
    }

    @Test("Response over 50KB is discarded")
    func oversizeDiscarded() async {
        let backend = RecordingBackend(responses: [String(repeating: "x", count: 60_000)])
        let service = LLMService(backend: backend, config: cloudConfig(), minInterval: 0)
        #expect(await service.query(systemPrompt: "s", userPrompt: "u", useCache: false) == nil)
        #expect(await backend.calls == 1)  // backend was called; the response was then discarded
    }

    @Test("Cloud provider sanitizes the prompt; loopback Ollama does not")
    func sanitizeGating() async {
        let secret = "exfil host 10.20.30.40 here"

        let cloudBackend = RecordingBackend(responses: ["ok"])
        let cloudSvc = LLMService(backend: cloudBackend, config: cloudConfig(), minInterval: 0)
        _ = await cloudSvc.query(systemPrompt: "s", userPrompt: secret, useCache: false)
        #expect(await cloudBackend.lastUserPrompt?.contains("10.20.30.40") == false)

        var local = LLMConfig(); local.provider = .ollama; local.ollamaURL = "http://127.0.0.1:11434"
        let localBackend = RecordingBackend(responses: ["ok"])
        let localSvc = LLMService(backend: localBackend, config: local, minInterval: 0)
        _ = await localSvc.query(systemPrompt: "s", userPrompt: secret, useCache: false)
        #expect(await localBackend.lastUserPrompt?.contains("10.20.30.40") == true)
    }

    @Test("Cache hit returns cached==true without a second backend call")
    func cacheWriteThrough() async {
        let backend = RecordingBackend(responses: ["hello"])
        let service = LLMService(backend: backend, config: cloudConfig(), minInterval: 0)
        let first = await service.query(systemPrompt: "s", userPrompt: "u", useCache: true)
        #expect(first?.response == "hello")
        #expect(first?.cached == false)
        let second = await service.query(systemPrompt: "s", userPrompt: "u", useCache: true)
        #expect(second?.response == "hello")
        #expect(second?.cached == true)
        #expect(await backend.calls == 1)  // second served from cache
    }

    @Test("Concurrent regular and extended calls keep one global interval")
    func concurrentCallsDoNotBurstAfterSharedSleep() async {
        let clock = ManualLLMRateLimitClock()
        let backend = RateLimitRecordingBackend(now: { await clock.now() })
        let service = LLMService(
            backend: backend,
            config: cloudConfig(),
            minInterval: 5,
            rateLimitClock: LLMRateLimitClock(
                now: { await clock.now() },
                sleep: { try await clock.sleep(for: $0) }
            )
        )

        let first = Task {
            await service.query(
                systemPrompt: "s", userPrompt: "first", useCache: false
            )
        }
        #expect(await eventually { await backend.snapshot().count == 1 })

        // Both callers observe the same last-call time and suspend for the
        // same five-second deadline. One uses each public backend path.
        let regular = Task {
            await service.query(
                systemPrompt: "s", userPrompt: "regular", useCache: false
            )
        }
        let extended = Task {
            await service.queryWithExtendedThinking(
                systemPrompt: "s", userPrompt: "extended"
            )
        }
        #expect(await eventually { await clock.sleeperCount == 2 })

        // Waking the burst admits exactly one caller. The other must recheck
        // the timestamp and sleep for a fresh interval instead of bursting.
        await clock.advance(by: 5)
        #expect(await eventually {
            let callCount = await backend.snapshot().count
            let sleeperCount = await clock.sleeperCount
            return callCount == 2 && sleeperCount == 1
        })

        await clock.advance(by: 5)
        _ = await first.value
        _ = await regular.value
        _ = await extended.value

        let invocations = await backend.snapshot().sorted { $0.time < $1.time }
        #expect(invocations.map(\.prompt).sorted() == ["extended", "first", "regular"])
        #expect(invocations.map(\.time) == [0, 5, 10])
    }
}
