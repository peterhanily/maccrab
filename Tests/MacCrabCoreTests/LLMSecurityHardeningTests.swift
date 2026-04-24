// LLMSecurityHardeningTests.swift
//
// Regression coverage for the v1.6.7 credential-audit fixes:
// - LLMSanitizer redacts API-key-shaped tokens + IPv6 private +
//   Mac ComputerName-style hostnames.
// - LLMConfig.description masks API keys so print(config) can't
//   leak credentials.
// - OllamaBackend.isPlaintextRemote correctly distinguishes
//   loopback from remote hosts for the Bearer-over-HTTP guard.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("LLMSanitizer: API key shapes")
struct SanitizerAPIKeyTests {

    @Test("Anthropic sk-ant- keys are redacted")
    func anthropic() {
        let input = "debug output: sk-ant-api03-EXAMPLE1234567890abcdef contains the token"
        let out = LLMSanitizer.sanitize(input)
        #expect(!out.contains("sk-ant-api03"))
        #expect(out.contains("[ANTHROPIC_KEY]"))
    }

    @Test("OpenAI sk- and sk-proj- keys are redacted")
    func openai() {
        let plain = LLMSanitizer.sanitize("key=sk-ABCDEFGHIJKLMNOPQRSTUVWX was leaked")
        #expect(plain.contains("[OPENAI_KEY]"))
        #expect(!plain.contains("sk-ABCDEFG"))

        let proj = LLMSanitizer.sanitize("key=sk-proj-QQQQQQQQQQQQQQQQQQQQQQQQQQ")
        #expect(proj.contains("[OPENAI_KEY]"))
    }

    @Test("Google AIza keys are redacted")
    func google() {
        // Exactly 35 chars after AIza — canonical Google API key length.
        let input = "config key: AIzaSyABCDEFGHIJKLMNOPQRSTUVWXYZabcdefg"
        let out = LLMSanitizer.sanitize(input)
        #expect(out.contains("[GOOGLE_KEY]"))
    }

    @Test("AWS access key prefixes are redacted")
    func awsAccessKey() {
        for prefix in ["AKIA", "ASIA", "AGPA", "ANPA"] {
            let key = "\(prefix)IOSFODNN7EXAMPLE"
            let out = LLMSanitizer.sanitize("credentials: \(key)")
            #expect(out.contains("[AWS_ACCESS_KEY]"), "Prefix \(prefix) must be redacted")
        }
    }

    @Test("GitHub tokens (ghp_, ghu_, github_pat_) are redacted")
    func github() {
        let classic = LLMSanitizer.sanitize("export GH=ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAA")
        #expect(classic.contains("[GITHUB_TOKEN]"))
        let fineGrained = LLMSanitizer.sanitize("github_pat_1234567890ABCDEFGHIJ_abcdefghijklmnopqrstuvwxyz")
        #expect(fineGrained.contains("[GITHUB_TOKEN]"))
    }

    @Test("Slack xox tokens are redacted")
    func slack() {
        let out = LLMSanitizer.sanitize("slack token: xoxb-12345-ABCDEFGHIJK-lmnopqrstuvw")
        #expect(out.contains("[SLACK_TOKEN]"))
    }

    @Test("Bearer tokens are redacted, keeping the word Bearer for context")
    func bearer() {
        let out = LLMSanitizer.sanitize("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.abcdefghijk")
        #expect(out.contains("Bearer [REDACTED]"))
        #expect(!out.contains("eyJhbGciOi"))
    }

    @Test("Bare words that look like keys are preserved — no over-redaction")
    func noFalsePositives() {
        // 20+ alphanumeric chars with a dash in the middle, but no
        // vendor prefix — must NOT be redacted.
        let input = "Rule fingerprint: dGVzdC1mb28tYmFyLWJhei1xdXV4"
        let out = LLMSanitizer.sanitize(input)
        #expect(out.contains("dGVzdC1mb28tYmFyLWJhei1xdXV4"))
    }
}

@Suite("LLMSanitizer: IPv6 and computer names")
struct SanitizerIPv6AndComputerTests {

    @Test("IPv6 link-local fe80:: is redacted")
    func linkLocal() {
        let out = LLMSanitizer.sanitize("neighbour at fe80::1234:5678 detected")
        #expect(out.contains("[PRIVATE_IPV6]"))
    }

    @Test("IPv6 unique-local fc00::/fd00:: is redacted")
    func uniqueLocal() {
        let out1 = LLMSanitizer.sanitize("peer fc00:abcd::1 woke")
        #expect(out1.contains("[PRIVATE_IPV6]"))
        let out2 = LLMSanitizer.sanitize("peer fd12:3456::7890:abcd")
        #expect(out2.contains("[PRIVATE_IPV6]"))
    }

    @Test("Public IPv6 (2001:db8::) is NOT redacted")
    func publicIPv6() {
        let out = LLMSanitizer.sanitize("remote 2001:db8::beef connected")
        #expect(out.contains("2001:db8"))
    }

    @Test("Mac ComputerName formats are redacted")
    func computerName() {
        for host in ["Peters-MacBook-Pro", "Adrians-Mac-mini", "Corp-Ops-iMac"] {
            let out = LLMSanitizer.sanitize("hostname: \(host) at 10.0.0.1")
            #expect(out.contains("[COMPUTER_NAME]"), "Computer name \(host) must be redacted")
        }
    }

    @Test("Non-Mac hyphenated words pass through")
    func hyphenatedCommonWords() {
        // Two words, neither is a Mac keyword — must not match.
        let out = LLMSanitizer.sanitize("multi-process design with multi-layer rules")
        #expect(out.contains("multi-process"))
        #expect(out.contains("multi-layer"))
    }
}

@Suite("LLMConfig: description masking")
struct LLMConfigMaskingTests {

    @Test("description hides full API key content")
    func descriptionMasksKeys() {
        var cfg = LLMConfig()
        cfg.claudeAPIKey = "sk-ant-SUPER-SECRET-VALUE-DO-NOT-LEAK"
        cfg.openaiAPIKey = "sk-ANOTHERTOPSECRETVALUE"
        let s = cfg.description
        #expect(!s.contains("SUPER-SECRET-VALUE-DO-NOT-LEAK"))
        #expect(!s.contains("ANOTHERTOPSECRETVALUE"))
        #expect(s.contains("claudeAPIKey=<len="))
        #expect(s.contains("openaiAPIKey=<len="))
    }

    @Test("debugDescription also redacts")
    func debugDescriptionRedacts() {
        var cfg = LLMConfig()
        cfg.geminiAPIKey = "AIzaSYFAKEKEYCONTENTXXXXXXXXXXXXXXXXXXXX"
        let s = String(reflecting: cfg)  // triggers debugDescription
        #expect(!s.contains("AIzaSYFAKEKEYCONTENT"))
    }

    @Test("String(describing: cfg) uses the masked description")
    func stringDescribingIsMasked() {
        var cfg = LLMConfig()
        cfg.mistralAPIKey = "very-secret-mistral-key-xyz"
        let s = String(describing: cfg)
        #expect(!s.contains("very-secret-mistral"))
    }

    @Test("Unset keys show <unset>, empty show <empty>")
    func emptyAndUnsetStates() {
        var cfg = LLMConfig()
        cfg.claudeAPIKey = ""
        let s = cfg.description
        #expect(s.contains("claudeAPIKey=<empty>"))
        #expect(s.contains("openaiAPIKey=<unset>"))
    }
}

@Suite("OllamaBackend: plaintext-remote guard")
struct OllamaPlaintextGuardTests {

    @Test("http://localhost is safe")
    func localhostSafe() {
        let url = URL(string: "http://localhost:11434")!
        #expect(!OllamaBackend.isPlaintextRemote(url))
    }

    @Test("http://127.0.0.1 is safe")
    func v4LoopbackSafe() {
        let url = URL(string: "http://127.0.0.1:11434")!
        #expect(!OllamaBackend.isPlaintextRemote(url))
    }

    @Test("http://[::1] is safe")
    func v6LoopbackSafe() {
        let url = URL(string: "http://[::1]:11434")!
        #expect(!OllamaBackend.isPlaintextRemote(url))
    }

    @Test("http://remote.host IS flagged")
    func remoteHttpFlagged() {
        let url = URL(string: "http://10.0.0.5:11434")!
        #expect(OllamaBackend.isPlaintextRemote(url))
    }

    @Test("https:// is always safe regardless of host")
    func httpsAlwaysSafe() {
        let url = URL(string: "https://remote.host.example.com:11434")!
        #expect(!OllamaBackend.isPlaintextRemote(url))
    }
}
