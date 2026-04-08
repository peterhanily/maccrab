// SecureURLSessionTests.swift
// Unit tests for SecureURLSession and APIProvider TLS pin configuration.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("SecureURLSession: TLS Configuration")
struct SecureURLSessionTests {

    // MARK: - Pin population

    @Test("All cloud providers have at least two SPKI pins (leaf + intermediate CA)")
    func cloudProviderPinCount() {
        let cloudProviders: [APIProvider] = [.anthropic, .openai, .gemini, .mistral, .virustotal, .shodan]
        for provider in cloudProviders {
            let pins = provider.knownSPKIPins
            #expect(pins.count >= 2,
                    "\(provider.rawValue) should have leaf + intermediate CA pins, got \(pins.count)")
        }
    }

    @Test("Ollama has no SPKI pins (local service)")
    func ollamaNoPin() {
        #expect(APIProvider.ollama.knownSPKIPins.isEmpty,
                "Ollama is local — no TLS pinning needed")
    }

    @Test("All pins are valid base64-encoded SHA-256 hashes (44 chars)")
    func pinFormat() {
        for provider in [APIProvider.anthropic, .openai, .gemini, .mistral, .virustotal, .shodan] {
            for pin in provider.knownSPKIPins {
                // A base64-encoded SHA-256 hash is exactly 44 characters (with = padding)
                #expect(pin.count == 44,
                        "\(provider.rawValue) pin '\(pin)' has wrong length: \(pin.count) (expected 44)")
                // Must be valid base64
                let decoded = Data(base64Encoded: pin)
                #expect(decoded != nil,
                        "\(provider.rawValue) pin '\(pin)' is not valid base64")
                // Decoded SHA-256 is exactly 32 bytes
                #expect(decoded?.count == 32,
                        "\(provider.rawValue) pin '\(pin)' decodes to \(decoded?.count ?? -1) bytes (expected 32)")
            }
        }
    }

    @Test("No duplicate pins within a provider")
    func noDuplicatePins() {
        for provider in [APIProvider.anthropic, .openai, .gemini, .mistral, .virustotal, .shodan] {
            let pins = provider.knownSPKIPins
            let uniquePins = Set(pins)
            #expect(uniquePins.count == pins.count,
                    "\(provider.rawValue) has duplicate SPKI pins")
        }
    }

    @Test("Anthropic and OpenAI share the same intermediate CA pin (Google Trust Services WE1)")
    func sharedIntermediateCA() {
        let anthropicPins = Set(APIProvider.anthropic.knownSPKIPins)
        let openaiPins = Set(APIProvider.openai.knownSPKIPins)
        let shared = anthropicPins.intersection(openaiPins)
        #expect(!shared.isEmpty,
                "Anthropic and OpenAI should share a Google Trust Services intermediate CA pin")
    }

    // MARK: - Session factory

    @Test("SecureURLSession.make returns a non-nil session for each provider")
    func sessionFactory() {
        let allProviders: [APIProvider] = [.anthropic, .openai, .gemini, .mistral, .virustotal, .shodan, .ollama]
        for provider in allProviders {
            let session = SecureURLSession.make(for: provider)
            // Request timeout should be set (30s) — if make() didn't crash, configuration is applied
            #expect(session.configuration.timeoutIntervalForRequest == 30,
                    "\(provider.rawValue) session should have 30s request timeout")
        }
    }

    @Test("Distinct providers get distinct session instances")
    func distinctSessions() {
        let s1 = SecureURLSession.make(for: .anthropic)
        let s2 = SecureURLSession.make(for: .openai)
        // Each call creates a new session; they should not be the same object
        #expect(s1 !== s2)
    }
}
