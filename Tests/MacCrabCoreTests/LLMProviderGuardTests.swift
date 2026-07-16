// LLMProviderGuardTests.swift
// MacCrabCoreTests
//
// The RC27 key-exfil guards: a cloud LLM backend must refuse a
// config-supplied endpoint host (OpenAI) or model name (Gemini) that
// could redirect the request — and the API key — to an attacker. These
// are pure allowlist checks; table-test the accept/reject matrix.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("LLM provider guards")
struct LLMProviderGuardTests {

    // MARK: - OpenAI baseURL host allowlist

    @Test("Accepts the canonical OpenAI + loopback hosts")
    func openAIAcceptsAllowed() {
        #expect(OpenAIBackend.isHostAllowed("api.openai.com"))
        #expect(OpenAIBackend.isHostAllowed("localhost"))
        #expect(OpenAIBackend.isHostAllowed("127.0.0.1"))
        #expect(OpenAIBackend.isHostAllowed("::1"))
        #expect(OpenAIBackend.isHostAllowed("API.OpenAI.com"))   // case-insensitive
    }

    @Test("Accepts Azure OpenAI subdomains but not the bare suffix")
    func openAIAzureSuffix() {
        #expect(OpenAIBackend.isHostAllowed("mycorp.openai.azure.com"))
        // The bare suffix has no subdomain label — must NOT match.
        #expect(OpenAIBackend.isHostAllowed(".openai.azure.com") == false)
    }

    @Test("Rejects look-alike and attacker-suffixed hosts")
    func openAIRejectsLookalikes() {
        #expect(OpenAIBackend.isHostAllowed("api.openai.com.attacker.com") == false)
        #expect(OpenAIBackend.isHostAllowed("openai.azure.com.attacker.com") == false)
        #expect(OpenAIBackend.isHostAllowed("evil.com") == false)
        #expect(OpenAIBackend.isHostAllowed("notapi.openai.com") == false)
        #expect(OpenAIBackend.isHostAllowed("") == false)
    }

    @Test("SPKI pinning applies ONLY to api.openai.com — allowlisted Azure/loopback use the unpinned session")
    func openAIPinsOnlyCanonicalHost() {
        // Pinning the api.openai.com SPKI would break TLS to these OTHER
        // allowlisted hosts, which can't present OpenAI's certificate key.
        #expect(OpenAIBackend.shouldPin(host: "api.openai.com"))
        #expect(OpenAIBackend.shouldPin(host: "API.OpenAI.com"))            // case-insensitive
        #expect(OpenAIBackend.shouldPin(host: "mycorp.openai.azure.com") == false)
        #expect(OpenAIBackend.shouldPin(host: "localhost") == false)
        #expect(OpenAIBackend.shouldPin(host: "127.0.0.1") == false)
        #expect(OpenAIBackend.shouldPin(host: nil) == false)
    }

    // MARK: - Gemini model-name allowlist

    @Test("Accepts well-formed model names")
    func geminiAcceptsValid() {
        #expect(GeminiBackend.isValidModelName("gemini-2.0-flash"))
        #expect(GeminiBackend.isValidModelName("gemini-1.5-pro_latest"))
        #expect(GeminiBackend.isValidModelName("gpt-4o.v2"))
    }

    @Test("OpenAI rejects an http:// base URL (cleartext key leak); keeps https + loopback")
    func openAIRejectsPlaintextRemote() {
        // https to the canonical host — accepted.
        #expect(OpenAIBackend(baseURL: "https://api.openai.com/v1", apiKey: "k").baseURL.scheme == "https")
        // http to the real host → Bearer key in cleartext → fall back to https.
        #expect(OpenAIBackend(baseURL: "http://api.openai.com/v1", apiKey: "k").baseURL.absoluteString == "https://api.openai.com/v1")
        // spoofed loopback → treated as remote → rejected.
        #expect(OpenAIBackend(baseURL: "http://127.0.0.1.evil.com/v1", apiKey: "k").baseURL.absoluteString == "https://api.openai.com/v1")
        // genuine loopback over http → allowed (local proxy / LM Studio).
        #expect(OpenAIBackend(baseURL: "http://localhost:1234/v1", apiKey: "k").baseURL.host == "localhost")
    }

    @Test("Rejects path-traversal / injection / oversized model names")
    func geminiRejectsBad() {
        #expect(GeminiBackend.isValidModelName("../../admin") == false)    // path traversal
        #expect(GeminiBackend.isValidModelName("models/x:generate") == false) // slash + colon
        #expect(GeminiBackend.isValidModelName("has space") == false)
        #expect(GeminiBackend.isValidModelName("") == false)
        #expect(GeminiBackend.isValidModelName(String(repeating: "a", count: 65)) == false) // > 64
        // Uppercase is rejected by the raw check — callers lowercase first.
        #expect(GeminiBackend.isValidModelName("Gemini-2.0") == false)
        #expect(GeminiBackend.isValidModelName("gemini-2.0"))
    }
}
