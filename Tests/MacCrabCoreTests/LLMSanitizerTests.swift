// LLMSanitizerTests.swift
// MacCrabCoreTests
//
// Acquisition audit (cloud-LLM data-handling P1) regression tests.
//
// The audit found the cloud-prompt redaction GUARANTEE was false in two
// ways:
//   (a) BARE usernames leaked — only `/Users/<name>/` paths were stripped,
//       so a free-standing `User: <name>` token went through verbatim.
//   (b) PUBLIC IPs leaked — only RFC-1918 / loopback / link-local / CGN
//       ranges were masked; routable addresses passed unredacted.
//
// These tests pin the fix: a prompt containing the live account name as a
// bare token, a public IPv4/IPv6, and a `/Users/<name>/` path all come out
// redacted — while the local Ollama provider is NOT sanitized at all.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("LLM cloud-prompt redaction (audit P1)")
struct LLMSanitizerAuditTests {

    // MARK: - Bare usernames + paths (finding 1a)

    @Test("Redacts the live account name as a BARE standalone token")
    func redactsBareUsername() {
        let user = NSUserName()
        // Skip on the (unlikely) CI edge where the account name is < 3 chars
        // and therefore intentionally not in the redaction set.
        guard user.count >= 3 else { return }

        // The exact shape LLMPrompts.baselineAnomalyUser emits.
        let out = LLMSanitizer.sanitize("User: \(user)")
        #expect(out.contains("[USER]"))
        #expect(!out.lowercased().contains(user.lowercased()))
    }

    @Test("Redacts the username inside a /Users/<name>/ path too")
    func redactsUserPath() {
        let user = NSUserName()
        guard user.count >= 3 else { return }
        let out = LLMSanitizer.sanitize("opened /Users/\(user)/Documents/secret.txt")
        #expect(out.contains("/Users/[USER]/"))
        #expect(!out.lowercased().contains("/users/\(user.lowercased())/"))
    }

    // MARK: - Public IPs (finding 1b)

    @Test("Redacts a routable public IPv4 (was leaking — only private masked)")
    func redactsPublicIPv4() {
        let out = LLMSanitizer.sanitize("C2 beacon to 203.0.113.42 observed")
        #expect(out.contains("[PUBLIC_IP]"))
        #expect(!out.contains("203.0.113.42"))
    }

    @Test("Still redacts private IPv4 as [PRIVATE_IP] (no regression)")
    func privateIPv4StillPrivate() {
        let out = LLMSanitizer.sanitize("lateral move from 192.168.1.10")
        #expect(out.contains("[PRIVATE_IP]"))
        #expect(!out.contains("192.168.1.10"))
    }

    @Test("Redacts a routable public IPv6")
    func redactsPublicIPv6() {
        let out = LLMSanitizer.sanitize("remote 2001:db8::beef connected")
        #expect(out.contains("[PUBLIC_IPV6]"))
        #expect(!out.lowercased().contains("2001:db8::beef"))
    }

    // MARK: - Combined audit-reproduction case

    @Test("A prompt with bare username + public IP + /Users path is fully scrubbed")
    func combinedAuditCase() {
        let user = NSUserName()
        guard user.count >= 3 else { return }
        let prompt = """
        Novel process lineage detected:
        User: \(user)
        Path: /Users/\(user)/.local/bin/agent
        Egress: connection to 8.8.8.8 then 2001:db8::1
        """
        let out = LLMSanitizer.sanitize(prompt)

        #expect(out.contains("[USER]"))
        #expect(out.contains("/Users/[USER]/"))
        #expect(out.contains("[PUBLIC_IP]"))
        #expect(out.contains("[PUBLIC_IPV6]"))

        #expect(!out.contains("8.8.8.8"))
        #expect(!out.contains("2001:db8::1"))
        // The bare username must not survive anywhere in the output.
        #expect(!out.lowercased().contains(user.lowercased()))
    }

    // MARK: - Over-redaction guard

    @Test("Does not redact ordinary prose or version-like triplets")
    func noOverRedaction() {
        // Three dotted groups (not four octets) must NOT match the IPv4 pass.
        let out = LLMSanitizer.sanitize("upgraded to rule pack v1.2.3 with multi-layer detection")
        #expect(out == "upgraded to rule pack v1.2.3 with multi-layer detection")
    }

    // MARK: - Local provider is NOT sanitized (finding scope)

    @Test("Local Ollama on loopback bypasses sanitization")
    func localOllamaNotSanitized() {
        var config = LLMConfig()
        config.provider = .ollama
        config.ollamaURL = "http://localhost:11434"
        config.sanitizeForCloud = true   // even with the flag on, local is exempt
        #expect(LLMService.shouldSanitize(for: config) == false)
    }

    @Test("Cloud providers ARE sanitized")
    func cloudProvidersSanitized() {
        for provider in [LLMProvider.claude, .openai, .mistral, .gemini] {
            var config = LLMConfig()
            config.provider = provider
            config.sanitizeForCloud = true
            #expect(LLMService.shouldSanitize(for: config) == true)
        }
    }

    @Test("A REMOTE Ollama is still sanitized (loopback-spoof guard)")
    func remoteOllamaSanitized() {
        var config = LLMConfig()
        config.provider = .ollama
        config.ollamaURL = "http://127.0.0.1.evil.com:11434"
        config.sanitizeForCloud = true
        #expect(LLMService.shouldSanitize(for: config) == true)
    }
}

@Suite("LLMSanitizer: strict-mode residual detector")
struct LLMSanitizerStrictModeTests {

    @Test("flags an unredacted high-entropy secret-shaped token")
    func flagsHighEntropyToken() {
        #expect(LLMSanitizer.hasResidualSensitiveContent("auth=Ab3Xk9Qz7Lm2Pw5Rt8Yn1Dv4Fg6Hj0Kc") == true)
        #expect(LLMSanitizer.hasResidualSensitiveContent("ya29.A0ARrdaMxKp9QwErTy7uIoP3aSdFgHjKlZxCvBnM") == true)
    }

    @Test("does NOT flag ordinary prose, paths, or already-redacted text")
    func ignoresBenign() {
        #expect(LLMSanitizer.hasResidualSensitiveContent("The process curl downloaded a file then executed it.") == false)
        #expect(LLMSanitizer.hasResidualSensitiveContent("/Users/alice/Documents/project/src/main.swift was modified") == false)
        #expect(LLMSanitizer.hasResidualSensitiveContent("api key was [REDACTED] before sending") == false)
        #expect(LLMSanitizer.hasResidualSensitiveContent("") == false)
        #expect(LLMSanitizer.hasResidualSensitiveContent("a short word list with normal english only") == false)
    }
}
