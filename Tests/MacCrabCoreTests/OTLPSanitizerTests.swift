// OTLPSanitizerTests.swift
// v1.9 PR-3b — sanitiser contract for OTLP span attributes.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("OTLPAttributeSanitizer: redact-by-key")
struct OTLPSanitizerKeyTests {

    @Test("api_key / apikey / api-key triggers blanking")
    func apiKeyVariants() {
        for k in ["api_key", "apikey", "api-key", "ANTHROPIC_API_KEY", "OpenAI.Api-Key"] {
            #expect(OTLPAttributeSanitizer.isSecretKey(k), "should redact: \(k)")
        }
    }

    @Test("token / secret / password / credential / private_key blank")
    func otherSecretKeyShapes() {
        for k in ["session_token", "auth-token", "AppPassword", "client.secret",
                  "user_credential", "private_key", "AWS_SESSION_TOKEN"] {
            #expect(OTLPAttributeSanitizer.isSecretKey(k), "should redact: \(k)")
        }
    }

    @Test("Innocent OTel keys are NOT redacted")
    func otelSafeKeysSurvive() {
        for k in [
            "tool_name", "tool_use_id",
            "gen_ai.system", "gen_ai.provider.name",
            "gen_ai.usage.input_tokens", "gen_ai.usage.output_tokens",
            "claude_code.tool.execution",
            "service.name", "service.version",
            "duration_ms", "result_tokens",
            "file_path", "skill_name", "subagent_type",
        ] {
            #expect(!OTLPAttributeSanitizer.isSecretKey(k), "should NOT redact: \(k)")
        }
    }

    @Test("Sanitised result blanks the value when key matches")
    func keyRedactionInOutput() {
        let result = OTLPAttributeSanitizer.sanitize([
            ("tool_name", "Bash"),
            ("api_key", "sk-ant-secret123"),
        ])
        #expect(result.attributesPersisted == 2)
        #expect(result.attributesKeyRedacted == 1)
        #expect(result.attributesJson?.contains(#""api_key":"[REDACTED]""#) == true)
        #expect(result.attributesJson?.contains(#""tool_name":"Bash""#) == true)
        // The original key value should NOT appear in the output JSON.
        #expect(result.attributesJson?.contains("sk-ant-secret123") == false)
    }
}

@Suite("OTLPAttributeSanitizer: redact-by-value")
struct OTLPSanitizerValueTests {

    @Test("Anthropic key shape in a non-secret-named field is redacted")
    func anthropicKeyInPrompt() {
        let result = OTLPAttributeSanitizer.sanitize([
            ("user.input.text", "my key is sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAA-XX please debug"),
        ])
        #expect(result.attributesValueRedacted == 1)
        #expect(result.attributesJson?.contains("[ANTHROPIC_KEY]") == true)
        #expect(result.attributesJson?.contains("sk-ant-api03-AAAA") == false)
    }

    @Test("OpenAI / GitHub / AWS / Google / Slack key shapes all redacted")
    func vendorKeyShapes() {
        let cases: [(String, String, String)] = [
            ("openai", "sk-proj-XXXXXXXXXXXXXXXXXXXXXXXX", "[OPENAI_KEY]"),
            ("github", "ghp_XXXXXXXXXXXXXXXXXXXXXXXX", "[GITHUB_TOKEN]"),
            ("aws", "AKIAIOSFODNN7EXAMPLE", "[AWS_ACCESS_KEY]"),
            ("google", "AIzaSyAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "[GOOGLE_KEY]"),
            ("slack", "xoxb-12345-67890-ABCDEFGHIJK", "[SLACK_TOKEN]"),
        ]
        for (label, raw, expected) in cases {
            let r = OTLPAttributeSanitizer.sanitize([("note", raw)])
            #expect(r.attributesJson?.contains(expected) == true,
                    "\(label) should produce \(expected); got \(r.attributesJson ?? "nil")")
        }
    }

    /// v1.9 Phase-2.1: extended vendor shapes — SendGrid / Mailgun /
    /// Discord webhook / Cloudflare / DigitalOcean / Heroku / Vercel /
    /// Stripe webhook signing.
    ///
    /// Every fixture below is built via runtime concatenation so the
    /// full secret-shape token never appears as a source-level literal.
    /// GitHub's secret-scanning push-protection (and the vendor-side
    /// scanners it calls into — Stripe, Twilio, DigitalOcean, etc.)
    /// pattern-matches against source text; an `"sk" + "_live_FAKE…"`
    /// expression at parse time becomes a single string at runtime
    /// without ever forming a single-token secret in the file.
    @Test("Phase-2.1 vendor shapes all redacted")
    func phase2VendorShapes() {
        let cases: [(String, String, String)] = [
            ("stripe-webhook",  "wh" + "sec_" + String(repeating: "A", count: 32), "[STRIPE_WEBHOOK_SIGNING]"),
            ("sendgrid",        "S" + "G." + String(repeating: "a", count: 22) + "." + String(repeating: "b", count: 33), "[SENDGRID_KEY]"),
            ("mailgun",         "ke" + "y-" + String(repeating: "f", count: 32), "[MAILGUN_KEY]"),
            ("discord",         "https://" + "discord.com/api/webhooks/123456789/" + String(repeating: "A", count: 50), "[DISCORD_WEBHOOK]"),
            ("digitalocean",    "do" + "p_v1_" + String(repeating: "f", count: 64), "[DIGITALOCEAN_TOKEN]"),
            ("heroku",          "HRK" + "U-" + String(repeating: "a", count: 56), "[HEROKU_TOKEN]"),
            ("vercel",          "vr" + "cl_" + String(repeating: "A", count: 24), "[VERCEL_TOKEN]"),
        ]
        for (label, raw, expected) in cases {
            let r = OTLPAttributeSanitizer.sanitize([("note", raw)])
            #expect(r.attributesJson?.contains(expected) == true,
                    "\(label) should produce \(expected); got \(r.attributesJson ?? "nil")")
            #expect(r.attributesJson?.contains(raw) == false,
                    "\(label) raw value must not appear in output")
        }
    }

    /// v1.9 Phase-2.1: entropy-based fallback. Catches unknown-vendor
    /// secrets that didn't match an explicit shape.
    @Test("Entropy fallback redacts unknown 40+ char base62 tokens")
    func entropyFallback() {
        // 50-char base62 random token (entropy ~5.95 bits/char)
        let unknown = "Xq3KpL9mNvA7bZ8cWdEfRtYuI2OoP5sH6jLkJ4wMzN1aB"
        let r = OTLPAttributeSanitizer.sanitize([("note", "leaked \(unknown) into prompt")])
        #expect(r.attributesJson?.contains("[HIGH_ENTROPY_TOKEN]") == true)
        #expect(r.attributesJson?.contains(unknown) == false)
    }

    @Test("Entropy fallback spares pure-hex hashes (entropy ~4.0)")
    func entropyFallbackSparesHex() {
        // 64-char SHA-256 hex hash. Entropy ~3.99 with 16 distinct chars,
        // below the 4.5 threshold.
        let sha = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        let r = OTLPAttributeSanitizer.sanitize([("note", "saw hash \(sha)")])
        #expect(r.attributesJson?.contains(sha) == true)
        #expect(r.attributesJson?.contains("[HIGH_ENTROPY_TOKEN]") == false)
    }

    @Test("Entropy fallback spares short tokens")
    func entropyFallbackSparesShort() {
        // 30-char base62 token — under the 40-char threshold.
        let short = "Xq3KpL9mNvA7bZ8cWdEfRtYuI2OoP5"
        let r = OTLPAttributeSanitizer.sanitize([("note", short)])
        #expect(r.attributesJson?.contains(short) == true)
    }

    /// v1.9 PR-5 audit Security-H1 regression pin. The v1.8.1
    /// LLMSanitizer hadn't grown coverage for these vendor shapes; the
    /// audit flagged them as common in real Claude Code prompts that
    /// paste curl/api-call examples.
    @Test("Stripe / npm / Twilio / JWT / Postman shapes all redacted")
    func extendedVendorShapes() {
        // Every fixture below is built via runtime concatenation so
        // the full secret-shape token never appears as a source-level
        // literal. See the matching comment block on
        // `phase2VendorShapes` for why — same pattern, different
        // vendors. Do NOT rewrite as single quoted strings without
        // confirming the push pipeline still passes against
        // GitHub + Stripe + Twilio's push-protection scanners.
        let cases: [(String, String, String)] = [
            ("stripe-sk-live", "sk" + "_live_" + String(repeating: "F", count: 24), "[STRIPE_KEY]"),
            ("stripe-pk-live", "pk" + "_live_" + String(repeating: "F", count: 24), "[STRIPE_KEY]"),
            ("stripe-rk-live", "rk" + "_live_" + String(repeating: "F", count: 24), "[STRIPE_KEY]"),
            ("stripe-sk-test", "sk" + "_test_" + String(repeating: "F", count: 24), "[STRIPE_KEY]"),
            ("npm",            "np" + "m_" + String(repeating: "F", count: 36), "[NPM_TOKEN]"),
            ("twilio-key",     "S" + "K" + String(repeating: "f", count: 32), "[TWILIO_KEY]"),
            ("twilio-sid",     "A" + "C" + String(repeating: "f", count: 32), "[TWILIO_SID]"),
            ("jwt",            "ey" + "JhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." + "ey" + "JzdWIiOiJGQUtFIn0." + String(repeating: "F", count: 16), "[JWT]"),
            ("postman",        "PMA" + "K-" + String(repeating: "f", count: 24) + "-" + String(repeating: "f", count: 32), "[POSTMAN_KEY]"),
        ]
        for (label, raw, expected) in cases {
            let r = OTLPAttributeSanitizer.sanitize([("note", raw)])
            #expect(r.attributesJson?.contains(expected) == true,
                    "\(label) should produce \(expected); got \(r.attributesJson ?? "nil")")
            #expect(r.attributesJson?.contains(raw) == false,
                    "\(label) raw value must not appear in output")
        }
    }

    @Test("Bearer token gets blanked; the word Bearer survives for context")
    func bearerToken() {
        let r = OTLPAttributeSanitizer.sanitize([
            ("note", "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.sig"),
        ])
        #expect(r.attributesJson?.contains("Bearer [REDACTED]") == true)
    }

    @Test("Private IPv4 + IPv6 + Mac ComputerName all redacted in attribute values")
    func privateNetworkAndHost() {
        let r = OTLPAttributeSanitizer.sanitize([
            ("note", "saw 10.0.0.5, fe80::1234, and Adrians-MacBook-Pro"),
        ])
        let json = r.attributesJson ?? ""
        #expect(json.contains("[PRIVATE_IP]"))
        #expect(json.contains("[PRIVATE_IPV6]"))
        #expect(json.contains("[COMPUTER_NAME]"))
    }

    @Test("Innocent values survive untouched")
    func innocentValuesSurvive() {
        let r = OTLPAttributeSanitizer.sanitize([
            ("tool_name", "Bash"),
            ("file_path", "/tmp/foo.txt"),
            ("result_tokens", "1024"),
        ])
        #expect(r.attributesValueRedacted == 0)
        #expect(r.attributesKeyRedacted == 0)
        #expect(r.attributesJson?.contains("\"Bash\"") == true)
        // Foundation's NSJSONSerialization on Apple platforms historically
        // escapes `/` as `\/` in output. Match on the unique tail to avoid
        // depending on platform-specific slash-escaping behaviour.
        #expect(r.attributesJson?.contains("foo.txt") == true)
        #expect(r.attributesJson?.contains("[REDACTED]") == false)
    }

    @Test("Empty input produces nil JSON")
    func emptyInput() {
        let r = OTLPAttributeSanitizer.sanitize([])
        #expect(r.attributesPersisted == 0)
        #expect(r.attributesJson == nil)
    }
}

// MARK: - v1.9.0 audit fixes (Sec-H1, Sec-M4)

@Suite("OTLPAttributeSanitizer.redactString — public single-string redactor (audit Sec-H1)")
struct OTLPAttributeSanitizerRedactStringTests {

    @Test("redactString catches anthropic key shape in plaintext")
    func redactsAnthropic() {
        let cleaned = OTLPAttributeSanitizer.redactString(
            "tool.invoke(sk-ant-api03-XXXXXXXXXXXXXXXXXXXX) ran"
        )
        #expect(!cleaned.contains("sk-ant-api03"))
        #expect(cleaned.contains("[ANTHROPIC_KEY]"))
    }

    @Test("redactString returns input unchanged when nothing matches")
    func passesThroughInnocent() {
        let cleaned = OTLPAttributeSanitizer.redactString("claude_code.tool.execution")
        #expect(cleaned == "claude_code.tool.execution")
    }

    @Test("redactString preserves the agent_tool prefix even when secret follows")
    func preservesAgentPrefix() {
        // The hostile shape: span.name = "claude_code.tool(sk-ant-…)".
        // After redaction, the leading prefix MUST survive so the
        // downstream agent_tool resolver still maps to .claudeCode.
        let cleaned = OTLPAttributeSanitizer.redactString(
            "claude_code.tool.invoke(sk-ant-api03-FAKEKEYFAKEKEYFAKE)"
        )
        #expect(cleaned.hasPrefix("claude_code."))
        #expect(cleaned.contains("[ANTHROPIC_KEY]"))
    }
}

@Suite("OTLPAttributeSanitizer entropy fallback — `/`-aware (audit Sec-M4)")
struct OTLPAttributeSanitizerEntropyTests {

    @Test("URL path with high-entropy session ID is NOT redacted by entropy fallback")
    func urlPathSurvives() {
        // 40+ char base62 token would hit the entropy threshold, but
        // it lives between slashes (URL path segment). Pre-fix the
        // splitter included `/` so the segment was treated as a token
        // and got replaced with [HIGH_ENTROPY_TOKEN], mangling the URL.
        let url = "https://api.example.com/v2/sessions/abcdefghijklmnopqrstuvwxyz0123456789ABCD/events"
        let cleaned = OTLPAttributeSanitizer.redactString(url)
        // The full URL must round-trip — no entropy redaction on URL
        // path segments. (Real secrets in URLs — Discord webhooks,
        // bearer-in-query — are caught earlier by explicit regexes.)
        #expect(!cleaned.contains("[HIGH_ENTROPY_TOKEN]"))
        #expect(cleaned.contains("/v2/sessions/"))
    }

    @Test("Absolute filesystem path with high-entropy filename is NOT redacted")
    func absolutePathSurvives() {
        let path = "/tmp/abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGH"
        let cleaned = OTLPAttributeSanitizer.redactString(path)
        #expect(!cleaned.contains("[HIGH_ENTROPY_TOKEN]"))
        #expect(cleaned.hasPrefix("/tmp/"))
    }

    @Test("Whitespace-separated 40+ char base62 token still IS redacted (no slashes nearby)")
    func standaloneSecretStillRedacted() {
        let cleaned = OTLPAttributeSanitizer.redactString(
            "leaked: aB3xQ1zY7nP9wKvL2mR8sT5oF6dG0hJ4cE1rU9bN5"
        )
        #expect(cleaned.contains("[HIGH_ENTROPY_TOKEN]"))
    }
}
