// CommandSanitizer.swift
// MacCrabCore
//
// Sanitizes command lines to remove potential credentials before
// sending to external systems (webhooks, syslog).

import Foundation

/// Sanitizes command lines to remove potential credentials before
/// sending to external systems (webhooks, syslog).
///
/// All regex patterns are compiled once as static constants to avoid
/// repeated compilation overhead on every call.
enum CommandSanitizer {

    private static let sensitiveArgumentFlags: Set<String> = [
        "--password", "--passwd", "--secret", "--token", "--auth",
        "--credential", "--api-key", "--api_key", "--apikey", "--key",
        "--access-key", "--access_key", "--secret-key", "--secret_key",
        "--private-key", "--private_key", "-p",
    ]

    // MARK: - Pre-compiled Patterns

    /// MySQL-style: `-p'password'`, `-p"password"`, or `-pPASSWORD` (no space).
    /// Captures the flag prefix so we can reconstruct it.
    private static let mysqlPasswordSingleQuote = try! NSRegularExpression(
        pattern: #"-p'[^']*'"#,
        options: []
    )

    private static let mysqlPasswordDoubleQuote = try! NSRegularExpression(
        pattern: #"-p"[^"]*""#,
        options: []
    )

    /// `-pVALUE` where VALUE is a non-whitespace sequence (no quotes).
    /// Must NOT match `-p` alone, `-p ` (space), or plain flags like `-port`.
    /// We require the value to contain at least one digit or special character,
    /// which distinguishes passwords like `-pS3cret!` from flags like `-path`.
    /// Quoted forms (`-p'...'` and `-p"..."`) are handled by earlier patterns.
    /// Uses a lookahead to assert the credential-like character exists somewhere
    /// in the value before consuming it.
    private static let mysqlPasswordBare = try! NSRegularExpression(
        pattern: #"(?<=\s)-p(?=[^\s]*[0-9!@#$%^&*()+])([^\s'"\-][^\s]*)"#,
        options: []
    )

    /// Long flags whose value is sensitive:
    /// `--password=VALUE`, `--secret=VALUE`, `--api-key=VALUE`, `--token=VALUE`,
    /// `--auth=VALUE`, `--key=VALUE`, `--credential=VALUE`, `--api_key=VALUE`,
    /// `--access-key=VALUE`, `--secret-key=VALUE`
    /// Handles `=value`, `="value"`, `='value'`, or `= value` (space-separated).
    private static let longFlagEquals = try! NSRegularExpression(
        pattern: #"--(password|secret|api[_-]?key|token|auth|key|credential|access[_-]?key|secret[_-]?key)\s*=\s*('[^']*'|"[^"]*"|[^\s]+)"#,
        options: .caseInsensitive
    )

    /// Long flags with space-separated value:
    /// `--password VALUE`, `--token VALUE`, etc.
    private static let longFlagSpace = try! NSRegularExpression(
        pattern: #"--(password|secret|api[_-]?key|token|auth|credential|access[_-]?key|secret[_-]?key)\s+('[^']*'|"[^"]*"|[^\s]+)"#,
        options: .caseInsensitive
    )

    /// URLs with embedded credentials: `://user:pass@host`
    private static let urlCredentials = try! NSRegularExpression(
        pattern: #"(://[^:@/\s]+:)([^@\s]+)(@)"#,
        options: []
    )

    /// AWS access key IDs: `AKIA` followed by exactly 16 uppercase alphanumeric chars.
    private static let awsAccessKey = try! NSRegularExpression(
        pattern: #"AKIA[A-Z0-9]{16}"#,
        options: []
    )

    /// GitHub tokens: `ghp_` or `ghs_` or `gho_` followed by 36+ alphanumeric chars.
    private static let githubToken = try! NSRegularExpression(
        pattern: #"gh[pso]_[A-Za-z0-9]{36,}"#,
        options: []
    )

    /// Bearer tokens in authorization-style arguments:
    /// `Bearer <token>` where token is alphanumeric with dots, dashes, underscores.
    private static let bearerToken = try! NSRegularExpression(
        pattern: #"(Bearer\s+)[A-Za-z0-9._\-]+"#,
        options: .caseInsensitive
    )

    /// Generic long secrets after `key=`, `secret=`, `token=`, `password=`,
    /// `credential=` with 8+ alphanumeric characters (catches env-style assignments).
    /// This is intentionally less aggressive than the flag patterns; it only matches
    /// when the key name is strongly indicative of a secret.
    private static let genericKeyValueSecret = try! NSRegularExpression(
        pattern: #"((?:^|[\s;,&|])((?:API[_-]?)?(?:KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL|PASSWD|AUTH)[_A-Z0-9]*)\s*=\s*)('[^']*'|"[^"]*"|[A-Za-z0-9/+=._\-]{8,})"#,
        options: .caseInsensitive
    )

    /// Base64-encoded strings after common sensitive flags (heuristic: 20+ base64
    /// chars that include mixed case, digits, and/or `+/=`).
    private static let base64AfterFlag = try! NSRegularExpression(
        pattern: #"(--(password|secret|token|key|auth|credential)\s*[=\s]\s*)([A-Za-z0-9+/]{20,}={0,2})"#,
        options: .caseInsensitive
    )

    // MARK: - Public API

    /// Redact sensitive patterns from a command line string.
    ///
    /// Applies a series of regex replacements to remove passwords, API keys,
    /// tokens, and other credentials from the command line. Returns the
    /// sanitized string with sensitive values replaced by `[REDACTED]` markers.
    ///
    /// - Parameter commandLine: The raw command line string to sanitize.
    /// - Returns: The sanitized command line with credentials redacted.
    static func sanitize(_ commandLine: String) -> String {
        var result = commandLine
        let fullRange = { NSRange(result.startIndex..., in: result) }

        // 1. MySQL-style `-p'password'` and `-p"password"`
        result = mysqlPasswordSingleQuote.stringByReplacingMatches(
            in: result, options: [], range: fullRange(),
            withTemplate: "-p'[REDACTED]'"
        )
        result = mysqlPasswordDoubleQuote.stringByReplacingMatches(
            in: result, options: [], range: fullRange(),
            withTemplate: #"-p"[REDACTED]""#
        )

        // 2. MySQL-style `-pVALUE` (bare, no quotes)
        result = mysqlPasswordBare.stringByReplacingMatches(
            in: result, options: [], range: fullRange(),
            withTemplate: "-p[REDACTED]"
        )

        // 3. Base64 after sensitive flags (before the generic long-flag patterns,
        //    so the more specific pattern matches first)
        result = base64AfterFlag.stringByReplacingMatches(
            in: result, options: [], range: fullRange(),
            withTemplate: "$1[REDACTED]"
        )

        // 4. Long flags with `=` separator: `--password=value`
        result = longFlagEquals.stringByReplacingMatches(
            in: result, options: [], range: fullRange(),
            withTemplate: "--$1=[REDACTED]"
        )

        // 5. Long flags with space separator: `--password value`
        result = longFlagSpace.stringByReplacingMatches(
            in: result, options: [], range: fullRange(),
            withTemplate: "--$1 [REDACTED]"
        )

        // 6. URL credentials: `://user:pass@host`
        result = urlCredentials.stringByReplacingMatches(
            in: result, options: [], range: fullRange(),
            withTemplate: "$1[REDACTED]$3"
        )

        // 7. AWS access key IDs
        result = awsAccessKey.stringByReplacingMatches(
            in: result, options: [], range: fullRange(),
            withTemplate: "[REDACTED_AWS_KEY]"
        )

        // 8. GitHub tokens
        result = githubToken.stringByReplacingMatches(
            in: result, options: [], range: fullRange(),
            withTemplate: "[REDACTED_GH_TOKEN]"
        )

        // 9. Bearer tokens
        result = bearerToken.stringByReplacingMatches(
            in: result, options: [], range: fullRange(),
            withTemplate: "$1[REDACTED]"
        )

        // 10. Generic KEY=VALUE secrets (env-style)
        result = genericKeyValueSecret.stringByReplacingMatches(
            in: result, options: [], range: fullRange(),
            withTemplate: "$1[REDACTED]"
        )

        return result
    }

    /// Redact argv with token boundaries intact. A command-line regex cannot
    /// protect `process.args` when the captured commandLine is empty, differs
    /// from argv, or stores a sensitive flag and its value in separate array
    /// elements.
    static func sanitize(arguments: [String]) -> [String] {
        var result: [String] = []
        result.reserveCapacity(arguments.count)
        var redactNext = false
        var optionsEnded = false

        for argument in arguments {
            if optionsEnded {
                result.append(sanitize(argument))
                continue
            }
            if argument == "--" {
                result.append(argument)
                redactNext = false
                optionsEnded = true
                continue
            }

            let lowered = argument.lowercased()
            // In argv, unlike a reconstructed command-line string, token
            // boundaries make MySQL's compact `-pVALUE` form unambiguous as a
            // single option/value unit. Conservatively redact every non-empty
            // compact `-p` token, including alphabetic passwords. This may hide
            // an unrelated one-dash option such as `-path`; at-rest credential
            // safety wins over preserving that uncommon spelling. `--` above
            // remains the explicit escape hatch for positional arguments.
            if lowered.hasPrefix("-p"),
               !lowered.hasPrefix("--"),
               argument.count > 2 {
                result.append("\(argument.prefix(2))[REDACTED]")
                redactNext = false
                continue
            }
            let flag = lowered.split(
                separator: "=",
                maxSplits: 1,
                omittingEmptySubsequences: false
            ).first.map(String.init) ?? lowered
            let isSensitiveFlag = sensitiveArgumentFlags.contains(flag)

            if redactNext, !isSensitiveFlag {
                result.append("[REDACTED]")
                redactNext = false
                continue
            }

            if isSensitiveFlag {
                if argument.contains("=") {
                    let originalFlag = argument.prefix {
                        $0 != "="
                    }
                    result.append("\(originalFlag)=[REDACTED]")
                    redactNext = false
                } else {
                    // A repeated sensitive flag is still a flag, not the prior
                    // flag's value. The final flag consumes the next ordinary
                    // token, preserving deterministic option structure.
                    result.append(argument)
                    redactNext = true
                }
                continue
            }
            result.append(sanitize(argument))
            redactNext = false
        }
        return result
    }
}
