// LLMSanitizer.swift
// MacCrabCore
//
// Redacts sensitive data (usernames, private IPs, hostnames, API-key-
// shaped tokens) from prompts before sending to cloud LLM APIs. Ollama
// (local) bypasses this, but every cloud-backend call runs through
// `sanitize()` first.
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
    private static let privateIPRegex = try! NSRegularExpression(
        pattern: #"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|127\.\d{1,3}\.\d{1,3}\.\d{1,3}|169\.254\.\d{1,3}\.\d{1,3})\b"#
    )
    /// IPv6 link-local (`fe80::/10`) and unique-local (`fc00::/7`,
    /// i.e. `fc..` or `fd..`). Matches compressed forms too. Loose on
    /// purpose — we'd rather over-redact a public address than leak a
    /// private one.
    private static let privateIPv6Regex = try! NSRegularExpression(
        pattern: #"\b(?:fe80|f[cd][0-9a-f]{2})(?::[0-9a-f]{0,4}){1,7}\b"#,
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
        result = redactPrivateIPs(result)
        result = redactPrivateIPv6(result)
        result = redactEmails(result)
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
        computerNameRegex.stringByReplacingMatches(
            in: text, range: NSRange(text.startIndex..., in: text),
            withTemplate: "[COMPUTER_NAME]"
        )
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

    private static func redactEmails(_ text: String) -> String {
        emailRegex.stringByReplacingMatches(
            in: text, range: NSRange(text.startIndex..., in: text),
            withTemplate: "[EMAIL]"
        )
    }
}
