// OllamaModelProbeTests.swift
// v1.17.4 — the pure tag-matching logic behind the boot-time Ollama model
// probe. Pre-fix the sysext defaulted to llama3.1:8b; if that model isn't
// pulled (the live host has only qwen2.5:7b) every call 404'd and the
// circuit breaker thrashed with no signal. The probe disables LLM cleanly
// when the configured model is known-absent — gated on this matcher.

import Testing
@testable import MacCrabCore

@Suite("OllamaBackend.modelTagMatches (v1.17.4)")
struct OllamaModelProbeTests {

    @Test("Exact tag present → match")
    func exact() {
        #expect(OllamaBackend.modelTagMatches(configured: "qwen2.5:7b",
                                              availableTags: ["qwen2.5:7b", "llama3.1:8b"]))
    }

    @Test("Configured model absent → no match (the live llama3.1:8b bug)")
    func absent() {
        #expect(!OllamaBackend.modelTagMatches(configured: "llama3.1:8b",
                                               availableTags: ["qwen2.5:7b"]))
    }

    @Test(":latest aliasing matches both directions")
    func latestAlias() {
        #expect(OllamaBackend.modelTagMatches(configured: "llama3.1",
                                              availableTags: ["llama3.1:latest"]))
        #expect(OllamaBackend.modelTagMatches(configured: "llama3.1:latest",
                                              availableTags: ["llama3.1"]))
    }

    @Test("Bare name does NOT match an arbitrary version tag (mirrors Ollama)")
    func bareDoesNotMatchVersion() {
        #expect(!OllamaBackend.modelTagMatches(configured: "llama3.1",
                                               availableTags: ["llama3.1:8b"]))
    }

    @Test("Matching is case-insensitive")
    func caseInsensitive() {
        #expect(OllamaBackend.modelTagMatches(configured: "Qwen2.5:7B",
                                              availableTags: ["qwen2.5:7b"]))
    }

    @Test("Empty tag list → no match")
    func emptyTags() {
        #expect(!OllamaBackend.modelTagMatches(configured: "qwen2.5:7b", availableTags: []))
    }
}
