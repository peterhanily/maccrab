// LLMSanitizer.swift
// MacCrabCore
//
// BEST-EFFORT redaction of sensitive data (real account usernames,
// home paths, private AND public IPs, hostnames, computer names,
// emails, CDHashes, API-key-shaped tokens) from prompts before sending
// to cloud LLM APIs. Ollama (local) bypasses this, but every cloud-
// backend call runs through `sanitize()` first.
//
// This is a heuristic scrubber, NOT a guarantee — novel data shapes can
// still slip through. Cloud LLM is off by default and opt-in; treat the
// sanitizer as defence-in-depth, not a contractual no-leak boundary.
// PRIVACY.md documents the user-facing claim.
//
// Acquisition audit (cloud-LLM data-handling P1): the prior version
// leaked (a) BARE usernames — only `/Users/<name>/` paths were stripped,
// so a `User: adrian` line went through verbatim — and (b) PUBLIC IPs,
// since only RFC-1918 / loopback / link-local / CGN ranges were masked.
// Both are now redacted (see `liveUsernames` and `redactPublicIPs`).
//
// v1.6.7: expanded the token-shape coverage after the credential audit.
// Previously the sanitizer caught usernames/hostnames/IPs/emails and
// relied on `CommandSanitizer`'s flag regex to catch `--api-key=…`
// style leaks. That doesn't help when the LLM prompt inlines a free-
// form event description containing a raw `sk-ant-…` key. Now we
// redact the key shapes directly, regardless of surrounding context.

import Foundation

public enum LLMSanitizer {

    // Precompiled once at load. Patterns are static literals — safe to force-try.
    private static let userPathRegex = try! NSRegularExpression(pattern: #"/Users/([^/\s]+)/"#)
    private static let hostnameRegex = try! NSRegularExpression(
        pattern: #"\b[a-zA-Z][\w\-]*\.(local|internal|corp|lan)\b"#
    )
    /// Includes RFC 1918 (10/8, 172.16/12, 192.168/16), loopback
    /// (127/8), link-local (169.254/16), AND RFC 6598 carrier-grade
    /// NAT (100.64.0.0/10 = 100.64-100.127). Tailscale, mobile
    /// hotspots, and many corporate VPNs assign in the CGN range; we
    /// don't want those leaking to cloud LLMs.
    private static let privateIPRegex = try! NSRegularExpression(
        pattern: #"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|127\.\d{1,3}\.\d{1,3}\.\d{1,3}|169\.254\.\d{1,3}\.\d{1,3}|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.\d{1,3}\.\d{1,3})\b"#
    )
    /// IPv6 link-local (`fe80::/10`) and unique-local (`fc00::/7`,
    /// i.e. `fc..` or `fd..`). Matches compressed forms too. Loose on
    /// purpose — we'd rather over-redact a public address than leak a
    /// private one.
    private static let privateIPv6Regex = try! NSRegularExpression(
        pattern: #"\b(?:fe80|f[cd][0-9a-f]{2})(?::[0-9a-f]{0,4}){1,7}\b"#,
        options: [.caseInsensitive]
    )
    /// ANY remaining IPv4 literal. Runs AFTER the private-IP pass, so by
    /// the time this fires the RFC-1918 / loopback / link-local / CGN
    /// addresses are already `[PRIVATE_IP]` placeholders — what's left
    /// is routable/public. The audit found public IPs (e.g. a C2 dest
    /// address in an alert) leaked verbatim to cloud LLMs because only
    /// private ranges were masked. Each octet is constrained to 0-255 so
    /// invalid quads (999.999.999.999) and >255-component build strings
    /// (10.15.7.1000) are NOT eaten; three-group versions (`1.2.3`) don't match
    /// the four-group anchor. A genuine 4-group all-<=255 version (`1.2.3.4`) is
    /// syntactically indistinguishable from an IPv4 literal and IS redacted —
    /// over-redaction biases SAFE for a cloud prompt (lose context, never leak).
    private static let anyIPv4Regex = try! NSRegularExpression(
        pattern: #"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"#
    )
    /// ANY remaining IPv6 literal — runs AFTER the private-IPv6 pass.
    /// Matches a run of hex/colon characters that EITHER contains a `::`
    /// (compressed form) OR is fully expanded with 7 colons (8 hextets).
    /// The leading lookbehind/trailing lookahead anchor on `[0-9a-f:]`
    /// (not `\b`, which is unreliable next to `:`) so the whole address
    /// is grabbed. The `::`-or-full requirement deliberately excludes
    /// `HH:MM:SS` clock times (3 colon groups, no `::`). Catches public /
    /// global-unicast addresses (e.g. `2001:db8::1`) the private pass left.
    private static let anyIPv6Regex = try! NSRegularExpression(
        pattern: #"(?<![0-9a-f:])(?=[0-9a-f:]*::|(?:[0-9a-f]{1,4}:){6}[0-9a-f]{1,4})[0-9a-f:]*[0-9a-f](?![0-9a-f:])"#,
        options: [.caseInsensitive]
    )
    private static let emailRegex = try! NSRegularExpression(
        pattern: #"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"#
    )

    // API-key shapes. Each vendor's format is distinctive enough that
    // the false-positive risk is low at ≥20-char prefixed tokens.
    private static let anthropicKeyRegex = try! NSRegularExpression(
        pattern: #"\bsk-ant-[A-Za-z0-9_\-]{20,}\b"#
    )
    private static let openaiKeyRegex = try! NSRegularExpression(
        pattern: #"\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,}\b"#
    )
    private static let googleKeyRegex = try! NSRegularExpression(
        pattern: #"\bAIza[0-9A-Za-z_\-]{35}\b"#
    )
    private static let awsAccessKeyRegex = try! NSRegularExpression(
        pattern: #"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASCA)[A-Z0-9]{16}\b"#
    )
    private static let githubTokenRegex = try! NSRegularExpression(
        // ghp_, gho_, ghu_, ghs_, ghr_, github_pat_
        pattern: #"\b(?:gh[pousr]_|github_pat_)[A-Za-z0-9_]{20,}\b"#
    )
    private static let slackTokenRegex = try! NSRegularExpression(
        pattern: #"\bxox[aboprs]-[A-Za-z0-9\-]{10,}\b"#
    )
    /// Bearer tokens in Authorization headers or log output. Catch the
    /// value, leave the `Bearer ` word so the redaction is still
    /// obvious in context.
    private static let bearerTokenRegex = try! NSRegularExpression(
        pattern: #"\bBearer\s+[A-Za-z0-9_\-\.=:+/]{20,}\b"#,
        options: [.caseInsensitive]
    )
    /// Mac host names from `scutil --get ComputerName` — typically
    /// `Peters-MacBook-Pro` / `Adrians-Mac-mini`. Heuristic: two-or-
    /// more hyphenated tokens, each capitalized, where at least one
    /// token matches a Mac family keyword. Conservative enough that
    /// it won't strip ordinary prose.
    private static let computerNameRegex = try! NSRegularExpression(
        pattern: #"\b([A-Z][a-z]+[a-z0-9]*-)+(MacBook-Pro|MacBook-Air|Mac-Pro|Mac-mini|Mac-Studio|iMac)\b"#
    )

    /// The same names in the human-readable `scutil --get ComputerName` form —
    /// `Adrian's Mac mini`, `Peter's MacBook Pro`. The hyphenated regex above
    /// missed these, so a live ComputerName passed through un-redacted (audit).
    private static let computerNameFriendlyRegex = try! NSRegularExpression(
        pattern: #"\b[A-Z][a-z]+(?:['’]s)?\s(?:MacBook\s(?:Pro|Air)|Mac\s(?:Pro|mini|Studio)|iMac)\b"#
    )

    /// The LIVE host identifiers (ComputerName + network host name), read once.
    /// Redacting these exact literals catches the real host name regardless of
    /// its shape — the robust complement to the heuristic regexes above. Filtered
    /// to >=4 chars so we never redact "" or a trivially-short name.
    private static let liveHostLiterals: [String] = {
        var names: [String] = []
        if let cn = Host.current().localizedName { names.append(cn) }   // "Adrian's Mac mini"
        let hn = Foundation.ProcessInfo.processInfo.hostName            // "adrians-mac-mini.local"
        names.append(hn)
        if let base = hn.split(separator: ".").first { names.append(String(base)) }
        return names.filter { $0.count >= 4 }
    }()

    /// The machine's REAL local account names. The path regex above only
    /// strips a name when it appears inside `/Users/<name>/`; the audit
    /// found bare-username leaks too (e.g. `User: adrian` emitted by
    /// `LLMPrompts.baselineAnomalyUser`, or a username embedded in a
    /// process arg / log line). Redacting standalone occurrences of the
    /// REAL account names — not a generic `\w+` regex — catches those
    /// without nuking ordinary words.
    ///
    /// Derived from the home directories under `/Users` plus
    /// `NSUserName()`. Gated to >= 3 chars and the shared/placeholder
    /// accounts are dropped, so we never word-boundary-redact "Shared",
    /// the `.localized` Spotlight dir, or a 1-2 char alias that would
    /// collide with prose.
    private static let liveUsernames: [String] = {
        var names = Set<String>()
        names.insert(NSUserName())
        if let entries = try? FileManager.default.contentsOfDirectory(atPath: "/Users") {
            for entry in entries { names.insert(entry) }
        }
        // Skip placeholder dirs AND common security-vocabulary words that are
        // sometimes used as account names — redacting every "admin"/"test"/"root"
        // in a prompt to [USER] would gut the analysis text. (v1.19.1 audit P2.)
        let skip: Set<String> = [
            "shared", "guest", "localized", ".localized",
            "admin", "administrator", "root", "user", "test", "dev", "ops",
            "app", "build", "ci", "runner", "service", "daemon", "system",
        ]
        return names
            .filter { $0.count >= 3 && !$0.hasPrefix(".") && !skip.contains($0.lowercased()) }
            // Longest first so a username that is a prefix of another
            // ("dan" vs "danielle") redacts the longer match first.
            .sorted { $0.count > $1.count }
    }()

    /// Word-boundary regexes for each real account name, built once.
    /// Word-boundary anchored so "danielle" doesn't get half-redacted by
    /// a "dan" account, and so substrings inside larger identifiers are
    /// left alone.
    private static let usernameRegexes: [NSRegularExpression] = {
        liveUsernames.compactMap { name in
            let escaped = NSRegularExpression.escapedPattern(for: name)
            return try? NSRegularExpression(
                pattern: #"(?<![\w.])"# + escaped + #"(?![\w.])"#,
                options: [.caseInsensitive]
            )
        }
    }()

    /// CDHash values — 40-char hex strings preceded by `cdhash=` /
    /// `CDHash:` / `cd_hash:`. CDHash maps 1:1 to malware family in
    /// research datasets (i.e. leaking it tells an LLM exactly which
    /// known binary the host ran). The leading-keyword anchor avoids
    /// stripping unrelated 40-char SHA-1 hashes that show up in git
    /// commit IDs / file integrity reports.
    private static let cdhashRegex = try! NSRegularExpression(
        pattern: #"\b(?:cdhash|cd_hash|CDHash)\s*[:=]\s*[A-Fa-f0-9]{40}\b"#
    )

    /// Sanitize a prompt payload for cloud API submission.
    public static func sanitize(_ text: String) -> String {
        // API keys FIRST — `CommandSanitizer` below catches
        // `--api-key=…` and `key=sk-…` by replacing the *whole*
        // flag-and-value token with `[REDACTED]`, which would
        // swallow the key bytes before this module's key-shape
        // regexes could see them. By redacting vendor-prefixed
        // key shapes up front, `sk-ant-…` becomes `[ANTHROPIC_KEY]`
        // regardless of whether it was surrounded by a flag.
        var result = redactAPIKeys(text)
        result = CommandSanitizer.sanitize(result)
        result = redactUserPaths(result)
        result = redactComputerNames(result)
        result = redactHostnames(result)
        result = redactEmails(result)        // emails before usernames so the
                                             // local-part isn't half-redacted
        result = redactUsernames(result)     // bare account names (audit fix)
        result = redactPrivateIPs(result)
        result = redactPrivateIPv6(result)
        result = redactPublicIPs(result)     // any remaining routable IPs (audit fix)
        result = redactCDHashes(result)
        return result
    }

    private static func redactAPIKeys(_ text: String) -> String {
        let replacements: [(NSRegularExpression, String)] = [
            (anthropicKeyRegex, "[ANTHROPIC_KEY]"),
            (openaiKeyRegex, "[OPENAI_KEY]"),
            (googleKeyRegex, "[GOOGLE_KEY]"),
            (awsAccessKeyRegex, "[AWS_ACCESS_KEY]"),
            (githubTokenRegex, "[GITHUB_TOKEN]"),
            (slackTokenRegex, "[SLACK_TOKEN]"),
            (bearerTokenRegex, "Bearer [REDACTED]"),
        ]
        var result = text
        for (regex, template) in replacements {
            result = regex.stringByReplacingMatches(
                in: result, range: NSRange(result.startIndex..., in: result),
                withTemplate: template
            )
        }
        return result
    }

    private static func redactUserPaths(_ text: String) -> String {
        userPathRegex.stringByReplacingMatches(
            in: text, range: NSRange(text.startIndex..., in: text),
            withTemplate: "/Users/[USER]/"
        )
    }

    private static func redactHostnames(_ text: String) -> String {
        hostnameRegex.stringByReplacingMatches(
            in: text, range: NSRange(text.startIndex..., in: text),
            withTemplate: "[HOSTNAME]"
        )
    }

    private static func redactComputerNames(_ text: String) -> String {
        var result = text
        // Exact live-host literals first (shape-independent, robust). Longest
        // first so a base name doesn't partially redact the full name.
        for literal in liveHostLiterals.sorted(by: { $0.count > $1.count }) {
            result = result.replacingOccurrences(
                of: literal, with: "[COMPUTER_NAME]", options: [.caseInsensitive])
        }
        // Then the hyphenated + friendly heuristic forms (for OTHER hosts whose
        // names appear in ingested logs, not just this machine's).
        for regex in [computerNameRegex, computerNameFriendlyRegex] {
            result = regex.stringByReplacingMatches(
                in: result, range: NSRange(result.startIndex..., in: result),
                withTemplate: "[COMPUTER_NAME]")
        }
        return result
    }

    private static func redactPrivateIPs(_ text: String) -> String {
        privateIPRegex.stringByReplacingMatches(
            in: text, range: NSRange(text.startIndex..., in: text),
            withTemplate: "[PRIVATE_IP]"
        )
    }

    private static func redactPrivateIPv6(_ text: String) -> String {
        privateIPv6Regex.stringByReplacingMatches(
            in: text, range: NSRange(text.startIndex..., in: text),
            withTemplate: "[PRIVATE_IPV6]"
        )
    }

    /// Redact every account name in `liveUsernames`. Runs each name's
    /// pre-built word-boundary regex; longest names first (the array is
    /// pre-sorted) so a short name that is a prefix of a longer one
    /// can't half-redact it.
    private static func redactUsernames(_ text: String) -> String {
        var result = text
        for regex in usernameRegexes {
            result = regex.stringByReplacingMatches(
                in: result, range: NSRange(result.startIndex..., in: result),
                withTemplate: "[USER]"
            )
        }
        return result
    }

    /// Redact any IPv4 / IPv6 literal still present after the private
    /// passes — i.e. routable/public addresses. Runs LAST among the IP
    /// passes so private-range placeholders are already in place.
    private static func redactPublicIPs(_ text: String) -> String {
        var result = anyIPv4Regex.stringByReplacingMatches(
            in: text, range: NSRange(text.startIndex..., in: text),
            withTemplate: "[PUBLIC_IP]"
        )
        result = anyIPv6Regex.stringByReplacingMatches(
            in: result, range: NSRange(result.startIndex..., in: result),
            withTemplate: "[PUBLIC_IPV6]"
        )
        return result
    }

    private static func redactEmails(_ text: String) -> String {
        emailRegex.stringByReplacingMatches(
            in: text, range: NSRange(text.startIndex..., in: text),
            withTemplate: "[EMAIL]"
        )
    }

    private static func redactCDHashes(_ text: String) -> String {
        cdhashRegex.stringByReplacingMatches(
            in: text, range: NSRange(text.startIndex..., in: text),
            withTemplate: "[CDHASH]"
        )
    }
}
