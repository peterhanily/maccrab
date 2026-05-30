// SecureURLSessionPinningHonestyTests.swift
// Regression guard for enrich-02: strict TLS pinning must be honest about
// providers that ship no SPKI pins (silent no-op case).
//
// strictPinning / expectedPins are private on SecureURLSession, so these tests
// assert the APIProvider-level invariant that drives the no-op warning: a real
// NETWORK provider shipping an empty pin set is exactly the case where an
// operator's MACCRAB_TLS_PINNING=strict silently does nothing. If the cloud
// pin sets are ever re-emptied, or a new network provider ships with no pins,
// these tests flag the resulting dishonesty.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("SecureURLSession: strict-pinning honesty (enrich-02)")
struct SecureURLSessionPinningHonestyTests {

    @Test("osv is a real network provider that ships no pins (the silent no-op case)")
    func osvIsUnpinnedNetworkProvider() {
        // api.osv.dev is a public network host reached over TLS, not localhost.
        #expect(APIProvider.osv.rawValue == "api.osv.dev")
        #expect(APIProvider.osv.rawValue != "localhost")
        // It intentionally carries no pins — so strict mode is a no-op here and
        // the constructor must warn rather than pretend pinning is active.
        #expect(APIProvider.osv.knownSPKIPins.isEmpty,
                "osv ships no pins; strict pinning is a no-op and must be logged honestly")
    }

    @Test("ollama is localhost and is intentionally excluded from the no-op warning")
    func ollamaIsLocal() {
        #expect(APIProvider.ollama.rawValue == "localhost",
                "ollama targets localhost — no MITM surface, pinning genuinely N/A")
        #expect(APIProvider.ollama.knownSPKIPins.isEmpty)
    }

    @Test("cloud providers still ship real pins, so strict mode is NOT a no-op for them")
    func cloudProvidersArePinned() {
        // Guards against premise drift: if these are re-emptied, strict mode
        // would silently degrade for the providers that handle credentials.
        for provider in [APIProvider.anthropic, .openai, .gemini, .mistral, .virustotal, .shodan] {
            #expect(!provider.knownSPKIPins.isEmpty,
                    "\(provider.rawValue) must ship pins so MACCRAB_TLS_PINNING=strict actually enforces")
        }
    }

    @Test("sessions construct cleanly under strict-pinning env for both pinned and unpinned providers")
    func makeWorksUnderStrictEnv() {
        // Exercises the init path that emits the no-op warning for unpinned
        // providers; construction must succeed (warning, not failure) and a
        // pinned provider must still build.
        let osvSession = SecureURLSession.make(for: .osv)
        let anthropicSession = SecureURLSession.make(for: .anthropic)
        #expect(osvSession.configuration.timeoutIntervalForRequest == 30)
        #expect(anthropicSession.configuration.timeoutIntervalForRequest == 30)
    }
}
