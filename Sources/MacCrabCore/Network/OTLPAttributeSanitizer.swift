// OTLPAttributeSanitizer.swift
// MacCrabCore
//
// v1.9 PR-3b — sanitises decoded OTLP span attributes before they reach
// `TraceStore`. Trust framing (Plan v3): the agent's OTel self-report is
// advisory, the kernel events are authoritative — but advisory data still
// gets stored, so we must redact secret-shaped values that an
// instrumentation bug or hostile agent could put into an attribute.
//
// Reuses the secret-shape regexes from `LLMSanitizer` indirectly: we
// special-case the same vendor key prefixes here so the boundary is clear
// (LLMSanitizer is the prompt-bound sanitiser, OTLPAttributeSanitizer is
// the wire-bound one). Behaviour drift between the two would be a v1.9
// audit-pass candidate.
//
// Defence-in-depth principles:
//   * Drop attributes whose KEY name signals secrets (case-insensitive
//     contains: "key", "token", "secret", "password", "credential", "auth",
//     "passwd"). The instrumented-value will be replaced with "[REDACTED]"
//     in the rendered JSON.
//   * Redact attribute VALUES that match known vendor key shapes regardless
//     of attribute key (an attribute key like "user.input.text" can
//     contain a leaked sk-ant-... that the user pasted).
//   * Redact private IPv4 / private IPv6 / Mac ComputerName patterns.
//   * Preserve OTel/agent-attributable fields verbatim — those are what
//     downstream rules and the dashboard need.

import Foundation

public struct OTLPSanitizationResult: Sendable, Equatable {
    /// Compact JSON `{"key1":"value1","key2":"value2"}` of the sanitised
    /// attribute set. Keys are sorted to make output deterministic for
    /// tests and for any future content-hashing.
    public let attributesJson: String?
    /// Attribute count actually persisted (post-redaction-by-key).
    public let attributesPersisted: Int
    /// Number of attributes whose KEY signalled secrets and were
    /// replaced with `[REDACTED]`.
    public let attributesKeyRedacted: Int
    /// Number of attributes whose VALUE was redacted (key looked OK but
    /// value matched a vendor token shape).
    public let attributesValueRedacted: Int
}

public enum OTLPAttributeSanitizer {

    // MARK: - Configuration

    /// Substring matches in attribute key names that trigger value
    /// blanking. Case-insensitive. The hits here are unambiguous: any
    /// attribute whose key name contains one of these will have its
    /// value blanked, regardless of where in the key the match falls.
    private static let secretKeySubstrings: [String] = [
        "secret",
        "password", "passwd",
        "credential",
    ]

    /// Segment-exact matches in attribute key names. The key is split on
    /// `[._\-]` (case-insensitive after lowercasing) and any segment that
    /// exactly equals one of these triggers blanking. This is the
    /// disambiguator that lets us catch `api_key`, `private_key`,
    /// `session_token`, `auth-token` while NOT catching
    /// `gen_ai.usage.input_tokens` or `result_tokens` (plural) or
    /// `tool_use_id`.
    private static let secretKeySegments: Set<String> = [
        "key", "token", "auth", "bearer", "apikey",
    ]

    // MARK: - Public API

    /// Take a list of (key, value) attributes, redact-by-key the secret
    /// shapes, redact-by-value the leaked tokens that slipped past the key
    /// gate, and emit a compact deterministic JSON string ready for the
    /// `attributes_json` column.
    public static func sanitize(_ attributes: [(String, String)]) -> OTLPSanitizationResult {
        var keyRedacted = 0
        var valueRedacted = 0
        var processed: [(String, String)] = []
        processed.reserveCapacity(attributes.count)

        for (key, rawValue) in attributes {
            if isSecretKey(key) {
                keyRedacted += 1
                processed.append((key, "[REDACTED]"))
                continue
            }
            let (cleanedValue, didRedact) = redactValue(rawValue)
            if didRedact { valueRedacted += 1 }
            processed.append((key, cleanedValue))
        }

        // Stable JSON: sort by key, then encode via Foundation's
        // JSONSerialization (no `JSONEncoder` because we're constructing
        // a flat string→string dict and don't need Codable).
        let sorted = processed.sorted { $0.0 < $1.0 }
        var dict: [String: String] = [:]
        dict.reserveCapacity(sorted.count)
        for (k, v) in sorted { dict[k] = v }
        var json: String? = nil
        if !dict.isEmpty,
           let data = try? JSONSerialization.data(
                withJSONObject: dict, options: [.sortedKeys]
           ),
           let str = String(data: data, encoding: .utf8) {
            json = str
        }
        return OTLPSanitizationResult(
            attributesJson: json,
            attributesPersisted: processed.count,
            attributesKeyRedacted: keyRedacted,
            attributesValueRedacted: valueRedacted
        )
    }

    /// Public for tests: case-insensitive secret-shape check on the
    /// attribute key. Returns true iff the key contains one of the
    /// unambiguous substrings (secret/password/credential) OR any of
    /// its dot/underscore/hyphen-separated segments exactly matches
    /// `key`/`token`/`auth`/`bearer`/`apikey`. Plural forms
    /// (`tokens`, `keys`) are intentionally not matched because they
    /// appear in legitimate OTel usage attributes (`input_tokens`,
    /// `output_tokens`).
    public static func isSecretKey(_ key: String) -> Bool {
        let lowered = key.lowercased()
        for s in secretKeySubstrings {
            if lowered.contains(s) { return true }
        }
        // Split on `.`, `_`, `-` and check each segment exactly.
        let segments = lowered.split(whereSeparator: { c in
            c == "." || c == "_" || c == "-"
        })
        for seg in segments {
            if secretKeySegments.contains(String(seg)) {
                return true
            }
        }
        return false
    }

    // MARK: - Value-side regex redaction

    private static let anthropicKey = try! NSRegularExpression(
        pattern: #"\bsk-ant-[A-Za-z0-9_\-]{20,}\b"#
    )
    private static let openaiKey = try! NSRegularExpression(
        pattern: #"\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,}\b"#
    )
    /// Google API keys are conventionally 39 chars (`AIza` + 35) but
    /// some test fixtures/leaks carry trailing characters. Match 35-or-
    /// more and let the trailing word boundary fall where the chars
    /// run out — same rationale as LLMSanitizer's matcher.
    private static let googleKey = try! NSRegularExpression(
        pattern: #"\bAIza[0-9A-Za-z_\-]{35,}\b"#
    )
    private static let awsAccessKey = try! NSRegularExpression(
        pattern: #"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASCA)[A-Z0-9]{16}\b"#
    )
    private static let githubToken = try! NSRegularExpression(
        pattern: #"\b(?:gh[pousr]_|github_pat_)[A-Za-z0-9_]{20,}\b"#
    )
    private static let slackToken = try! NSRegularExpression(
        pattern: #"\bxox[aboprs]-[A-Za-z0-9\-]{10,}\b"#
    )
    private static let bearerToken = try! NSRegularExpression(
        pattern: #"\bBearer\s+[A-Za-z0-9_\-\.=:+/]{20,}\b"#,
        options: [.caseInsensitive]
    )
    // v1.9 PR-5 audit (Security-H1): vendor key shapes that the v1.8.1
    // LLMSanitizer had not added yet. Common in agent prompts that
    // paste curl/api-call examples — slipping past the sanitiser would
    // persist a working secret into traces.db.
    private static let stripeKey = try! NSRegularExpression(
        // sk_live_/sk_test_/pk_live_/pk_test_/rk_live_/rk_test_
        // followed by 24+ alphanumeric chars
        pattern: #"\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{24,}\b"#
    )
    private static let stripeRestrictedKey = try! NSRegularExpression(
        // rk_live_ / rk_test_ overlap covered above; this catches the
        // longer Stripe restricted-API-key shape if present.
        pattern: #"\bsk_test_[A-Za-z0-9]{24,}\b"#
    )
    private static let npmToken = try! NSRegularExpression(
        // npm_ + 36 mixed-case alphanumeric — npm publish tokens.
        pattern: #"\bnpm_[A-Za-z0-9]{36}\b"#
    )
    private static let twilioApiKey = try! NSRegularExpression(
        // SK + 32 hex (Twilio API key SID + auth-token shapes)
        pattern: #"\bSK[0-9a-fA-F]{32}\b"#
    )
    private static let twilioAccountSid = try! NSRegularExpression(
        pattern: #"\bAC[0-9a-fA-F]{32}\b"#
    )
    /// JWT — three base64url segments separated by dots, with the first
    /// segment starting `eyJ` (the magic that says "{" in base64url).
    /// Bound the lengths so we don't false-positive on URL fragments.
    private static let jwtToken = try! NSRegularExpression(
        pattern: #"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b"#
    )
    private static let postmanKey = try! NSRegularExpression(
        // PMAK-<24 hex>-<32+ hex>. Postman API key shape; the second
        // segment length varies between revisions, so accept >=30.
        pattern: #"\bPMAK-[A-Fa-f0-9]{24}-[A-Fa-f0-9]{30,}\b"#
    )
    // v1.9 Phase-2.1: extended vendor coverage. Each prefix is
    // distinctive enough that a >=20-char tail bounds the FP rate to
    // near zero. Several were field-reported as appearing in real
    // Claude Code prompt context (curl/api-call examples).
    private static let stripeWebhookSigning = try! NSRegularExpression(
        pattern: #"\bwhsec_[A-Za-z0-9]{32,}\b"#
    )
    private static let sendgridKey = try! NSRegularExpression(
        // SG. + base64-ish 22 chars + . + base64-ish 43 chars
        pattern: #"\bSG\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{30,}\b"#
    )
    private static let mailgunKey = try! NSRegularExpression(
        // key-<32 hex>
        pattern: #"\bkey-[A-Fa-f0-9]{32}\b"#
    )
    private static let discordWebhook = try! NSRegularExpression(
        // discord webhook URLs carry a long token in the path; they
        // are not API keys per se but are equivalently sensitive.
        pattern: #"https://discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_\-]{40,}"#
    )
    private static let cloudflareApiToken = try! NSRegularExpression(
        // Cloudflare scoped API tokens: 40 chars base62 (no dashes).
        // CF_TOKEN= prefix is operator-set; we match the value shape.
        pattern: #"\bCF[A-Za-z0-9_\-]{40,}\b"#
    )
    private static let digitalOceanToken = try! NSRegularExpression(
        // dop_v1_<64 hex>
        pattern: #"\bdop_v1_[A-Fa-f0-9]{60,}\b"#
    )
    private static let herokuToken = try! NSRegularExpression(
        // HRKU- + 56 base64 chars
        pattern: #"\bHRKU-[A-Za-z0-9_\-]{50,}\b"#
    )
    private static let vercelToken = try! NSRegularExpression(
        // vrcl_<24+ alphanumeric>; sometimes shown as "vercel_..." on
        // older versions.
        pattern: #"\bv(?:rcl|ercel)_[A-Za-z0-9]{24,}\b"#
    )
    private static let privateIPv4 = try! NSRegularExpression(
        pattern: #"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|169\.254\.\d{1,3}\.\d{1,3})\b"#
    )
    private static let privateIPv6 = try! NSRegularExpression(
        pattern: #"\b(?:fe80|f[cd][0-9a-f]{2})(?::[0-9a-f]{0,4}){1,7}\b"#,
        options: [.caseInsensitive]
    )
    private static let computerName = try! NSRegularExpression(
        pattern: #"\b([A-Z][a-z]+[a-z0-9]*-)+(MacBook-Pro|MacBook-Air|Mac-Pro|Mac-mini|Mac-Studio|iMac)\b"#
    )

    // v1.9 PR-5 audit (Performance-H4): promoted the replacements list
    // to a static let so we don't rebuild a 13-element array literal on
    // every attribute value. Order matters — more specific patterns
    // first so they don't get partly consumed by broader ones.
    private static let valueReplacements: [(NSRegularExpression, String)] = [
        (anthropicKey,         "[ANTHROPIC_KEY]"),
        (openaiKey,            "[OPENAI_KEY]"),
        (googleKey,            "[GOOGLE_KEY]"),
        (awsAccessKey,         "[AWS_ACCESS_KEY]"),
        (githubToken,          "[GITHUB_TOKEN]"),
        (slackToken,           "[SLACK_TOKEN]"),
        (stripeWebhookSigning, "[STRIPE_WEBHOOK_SIGNING]"),
        (stripeKey,            "[STRIPE_KEY]"),
        (stripeRestrictedKey,  "[STRIPE_KEY]"),
        (npmToken,             "[NPM_TOKEN]"),
        (twilioApiKey,         "[TWILIO_KEY]"),
        (twilioAccountSid,     "[TWILIO_SID]"),
        (jwtToken,             "[JWT]"),
        (postmanKey,           "[POSTMAN_KEY]"),
        (sendgridKey,          "[SENDGRID_KEY]"),
        (mailgunKey,           "[MAILGUN_KEY]"),
        (discordWebhook,       "[DISCORD_WEBHOOK]"),
        (cloudflareApiToken,   "[CLOUDFLARE_TOKEN]"),
        (digitalOceanToken,    "[DIGITALOCEAN_TOKEN]"),
        (herokuToken,          "[HEROKU_TOKEN]"),
        (vercelToken,          "[VERCEL_TOKEN]"),
        (bearerToken,          "Bearer [REDACTED]"),
        (privateIPv4,          "[PRIVATE_IP]"),
        (privateIPv6,          "[PRIVATE_IPV6]"),
        (computerName,         "[COMPUTER_NAME]"),
    ]

    /// Public single-string redactor. Used by `OTLPSpanExtractor` on
    /// the four free-form span identity fields (`service.name`,
    /// `span.name`, `gen_ai.provider.name`, `gen_ai.system`) which
    /// land in plaintext columns and aren't protected by the
    /// `attributes_json` AES-GCM encryption. Returns the input
    /// unchanged when no redaction happens.
    public static func redactString(_ value: String) -> String {
        let (cleaned, _) = redactValue(value)
        return cleaned
    }

    /// Apply each vendor regex; return (cleaned, didRedact).
    /// v1.9 PR-5 audit (Performance-H4): single-pass `stringByReplacingMatches`
    /// — the prior code did a `firstMatch` probe followed by a full replace,
    /// running each regex twice on every value. `stringByReplacingMatches`
    /// returns the unchanged string when there's no match, so we count
    /// matches once via `numberOfMatches` and skip the replace when zero.
    internal static func redactValue(_ value: String) -> (String, Bool) {
        var working = value
        var didRedact = false
        for (regex, template) in valueReplacements {
            let nsRange = NSRange(working.startIndex..., in: working)
            if regex.numberOfMatches(in: working, range: nsRange) > 0 {
                didRedact = true
                working = regex.stringByReplacingMatches(
                    in: working, range: nsRange, withTemplate: template
                )
            }
        }
        // v1.9 Phase-2.1: entropy-based fallback. Catches unknown-vendor
        // secrets that didn't match any of the explicit shapes above.
        // Conservative: 40+ char tokens, base62-or-symbol, Shannon
        // entropy >= 4.5 bits/char. 4.5 cleanly excludes pure hex
        // (max 4.0 with 16 distinct chars) so we don't over-redact
        // SHA-256 hashes / git commits / known structured IDs.
        let (entropyCleaned, entropyHit) = redactHighEntropyTokens(working)
        if entropyHit {
            didRedact = true
            working = entropyCleaned
        }
        return (working, didRedact)
    }

    /// Token-level entropy redactor. Splits the value on whitespace +
    /// common delimiters, examines each token's Shannon entropy, and
    /// replaces qualifying tokens with `[HIGH_ENTROPY_TOKEN]`.
    ///
    /// v1.9.0 (audit Sec-M4): `/` is no longer a separator. URL paths
    /// (`https://example.com/api/v2/<long-session-id>`) and absolute
    /// filesystem paths (`/tmp/<uuid-pattern>`) routinely contain
    /// high-entropy segments that aren't secrets — pre-fix, qualifying
    /// segments got replaced with `[HIGH_ENTROPY_TOKEN]`, mangling
    /// legitimate URL/path attributes. Real secrets that DO live next
    /// to slashes (Discord webhook URLs, JWT-in-Authorization headers)
    /// are caught earlier by the explicit vendor regexes that DO
    /// understand the surrounding shape.
    private static func redactHighEntropyTokens(_ value: String) -> (String, Bool) {
        // Split on whitespace + structural punctuation that wouldn't
        // appear inside a real API key. We DO allow `-` and `_`
        // because real keys frequently contain those.
        let separators = CharacterSet(charactersIn: " \t\n\r,;()[]{}<>\"'`|\\:@!?")
        let parts = value.components(separatedBy: separators)
        var redactedAny = false
        var rebuilt = value
        for token in parts where token.count >= 40 {
            // Cheap first-pass shape filter — if the token has any non
            // base62/_-/. char, skip. Real keys almost always live in
            // this alphabet.
            guard token.allSatisfy({ $0.isLetter || $0.isNumber || $0 == "_" || $0 == "-" || $0 == "." }) else {
                continue
            }
            // Compute Shannon entropy in bits/char.
            var counts: [Character: Int] = [:]
            for c in token { counts[c, default: 0] += 1 }
            let total = Double(token.count)
            var entropy = 0.0
            for c in counts.values {
                let p = Double(c) / total
                entropy -= p * log2(p)
            }
            // 4.5 bits/char threshold — empirically separates structured
            // strings (CamelCaseIDs ~3.5, hex ~4.0) from base62 random
            // tokens (>=4.5 typically).
            guard entropy >= 4.5 else { continue }
            rebuilt = rebuilt.replacingOccurrences(of: token, with: "[HIGH_ENTROPY_TOKEN]")
            redactedAny = true
        }
        return (rebuilt, redactedAny)
    }
}
