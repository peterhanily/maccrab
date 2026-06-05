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

@Suite("LLMService safety envelope")
struct LLMServiceEnvelopeTests {

    private func cloudConfig() -> LLMConfig {
        var c = LLMConfig(); c.provider = .claude; c.sanitizeForCloud = true; return c
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
}
