// LoopbackEndpointTests.swift
// MacCrabCoreTests
//
// Pin the strict loopback classifier that gates engine-side LLM
// endpoints (SSRF/exfil), the Ollama plaintext-key guard, and
// LLMService prompt sanitization. The whole point is that a textual
// `hasPrefix("127.")` test is NOT enough — these payloads must be
// rejected as remote even though they begin with "127." or contain
// "127.0.0.1" as a left-most label.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("LoopbackEndpoint")
struct LoopbackEndpointTests {

    // MARK: - Genuine loopback hosts (accepted)

    @Test("localhost is loopback")
    func localhost() {
        #expect(LoopbackEndpoint.isLoopback(host: "localhost"))
        #expect(LoopbackEndpoint.isLoopback(host: "LOCALHOST"))
    }

    @Test("127.0.0.1 and the wider 127.0.0.0/8 block are loopback")
    func ipv4LoopbackBlock() {
        #expect(LoopbackEndpoint.isLoopback(host: "127.0.0.1"))
        #expect(LoopbackEndpoint.isLoopback(host: "127.0.0.2"))
        #expect(LoopbackEndpoint.isLoopback(host: "127.1.2.3"))
        #expect(LoopbackEndpoint.isLoopback(host: "127.255.255.255"))
    }

    @Test("::1 is loopback")
    func ipv6Loopback() {
        #expect(LoopbackEndpoint.isLoopback(host: "::1"))
    }

    // MARK: - Bypass payloads (rejected) — the LLM-1 regression

    @Test("attacker hostnames beginning with 127. are NOT loopback")
    func prefixBypassRejected() {
        #expect(!LoopbackEndpoint.isLoopback(host: "127.0.0.1.evil.com"))
        #expect(!LoopbackEndpoint.isLoopback(host: "127.evil.com"))
        #expect(!LoopbackEndpoint.isLoopback(host: "127.0.0.1.attacker.io"))
    }

    @Test("non-loopback IPs and ordinary hosts are rejected")
    func nonLoopbackRejected() {
        #expect(!LoopbackEndpoint.isLoopback(host: "10.0.0.5"))
        #expect(!LoopbackEndpoint.isLoopback(host: "192.168.1.10"))
        #expect(!LoopbackEndpoint.isLoopback(host: "126.0.0.1"))   // off-by-one below 127
        #expect(!LoopbackEndpoint.isLoopback(host: "128.0.0.1"))   // off-by-one above 127
        #expect(!LoopbackEndpoint.isLoopback(host: "example.com"))
        #expect(!LoopbackEndpoint.isLoopback(host: ""))
    }

    @Test("malformed dotted-quad lookalikes are rejected, not parsed as loopback")
    func malformedRejected() {
        // inet_pton rejects these, so they fall through to the DNS path.
        #expect(!LoopbackEndpoint.isLoopback(host: "1270.0.0.1"))
        #expect(!LoopbackEndpoint.isLoopback(host: "127.0.0"))
        #expect(!LoopbackEndpoint.isLoopback(host: "127"))
    }

    // MARK: - URL convenience overload

    @Test("URL overload classifies the parsed host, defeating prefix bypass")
    func urlOverload() {
        #expect(LoopbackEndpoint.isLoopback(urlString: "http://localhost:11434"))
        #expect(LoopbackEndpoint.isLoopback(urlString: "http://127.0.0.1:11434/api"))
        #expect(LoopbackEndpoint.isLoopback(urlString: "http://[::1]:11434"))
        #expect(!LoopbackEndpoint.isLoopback(urlString: "http://127.0.0.1.evil.com:11434"))
        #expect(!LoopbackEndpoint.isLoopback(urlString: "https://api.openai.com"))
        #expect(!LoopbackEndpoint.isLoopback(urlString: "not a url"))
    }

    // MARK: - OllamaBackend plaintext-key guard rides the same classifier

    @Test("Ollama plaintext-key guard treats the prefix-bypass host as remote")
    func ollamaPlaintextGuard() {
        #expect(OllamaBackend.isPlaintextRemote(URL(string: "http://127.0.0.1.evil.com:11434")!))
        #expect(!OllamaBackend.isPlaintextRemote(URL(string: "http://127.0.0.1:11434")!))
        #expect(!OllamaBackend.isPlaintextRemote(URL(string: "http://localhost:11434")!))
        // https to a remote host is fine — TLS protects the token.
        #expect(!OllamaBackend.isPlaintextRemote(URL(string: "https://ollama.example.com")!))
    }
}
