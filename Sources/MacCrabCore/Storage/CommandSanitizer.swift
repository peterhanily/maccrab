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
        "--private-key", "--private_key",
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
        pattern: #"--(password|passwd|secret|api[_-]?key|token|auth|key|credential|access[_-]?key|secret[_-]?key|private[_-]?key)\s*=\s*('[^']*'|"[^"]*"|[^\s]+)"#,
        options: .caseInsensitive
    )

    /// Long flags with space-separated value:
    /// `--password VALUE`, `--token VALUE`, etc.
    private static let longFlagSpace = try! NSRegularExpression(
        pattern: #"--(password|passwd|secret|api[_-]?key|token|auth|key|credential|access[_-]?key|secret[_-]?key|private[_-]?key)\s+('[^']*'|"[^"]*"|[^\s]+)"#,
        options: .caseInsensitive
    )

    /// `sshpass -p VALUE` and `sshpass -pVALUE`. sshpass's `-p` always takes
    /// the password; in a bare string another program's `-p` is ambiguous.
    private static let sshpassPassword = try! NSRegularExpression(
        pattern: #"(\bsshpass\b[^\n]*?\s-p)\s*('[^']*'|"[^"]*"|\S+)"#,
        options: []
    )

    /// `user:password` after curl/wget-style `-u`, `--user` or `--proxy-user`.
    /// Only an all-numeric pair is a uid:gid (`docker run -u 501:20`); a
    /// numeric password after a named user (`-u admin:123456`) is redacted.
    private static let userPasswordFlag = try! NSRegularExpression(
        pattern: #"((?:^|\s)(?:--user|--proxy-user|-u)(?:\s+|=)?['"]?(?![0-9]+:[0-9]+['"]?(?:\s|$))[^\s:'"]+:)([^\s'"]+)"#,
        options: []
    )

    /// OpenSSL passphrase arguments: `-passin pass:VALUE`, `-passout pass:VALUE`.
    private static let opensslPass = try! NSRegularExpression(
        pattern: #"((?:^|\s)pass:)(\S+)"#,
        options: []
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
        memo.value(for: commandLine, transform: applyRedactors)
    }

    /// Process command lines and arguments repeat on every event from that
    /// process; the redactors below are pure, so their output is replayed.
    private static let memo = DigestKeyedStringMemo(
        capacity: 512,
        maximumInputBytes: 4_096
    )

    /// Internal (not private) only so the memo parity test can call the suite
    /// directly as its uncached oracle.
    static func applyRedactors(_ commandLine: String) -> String {
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

        // 5b. Program- and pair-specific password arguments
        result = sshpassPassword.stringByReplacingMatches(
            in: result, options: [], range: fullRange(),
            withTemplate: "$1 [REDACTED]"
        )
        result = userPasswordFlag.stringByReplacingMatches(
            in: result, options: [], range: fullRange(),
            withTemplate: "$1[REDACTED]"
        )
        result = opensslPass.stringByReplacingMatches(
            in: result, options: [], range: fullRange(),
            withTemplate: "$1[REDACTED]"
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
        sanitize(arguments: arguments, leaf: sanitize)
    }

    /// The argv walk with its per-token redactor as a parameter, so the memo
    /// parity test can run the same walk over the uncached suite.
    static func sanitize(arguments: [String], leaf: (String) -> String) -> [String] {
        var result: [String] = []
        result.reserveCapacity(arguments.count)
        var redactNext = false
        var redactNextIsPasswordP = false
        var userPairNext = false
        var optionsEnded = false
        // Whether a program seen so far takes its password through `-p` or
        // `-P`. A wrapper (`sudo`, `docker exec db`) puts it after argv[0].
        var lowerPIsPassword = false
        var upperPIsPassword = false

        for argument in arguments {
            if !argument.hasPrefix("-"), !redactNext, !userPairNext {
                let program = programName(argument)
                if passwordLowerPPrograms.contains(program) {
                    lowerPIsPassword = true
                    optionsEnded = false  // a new command's argv: `kubectl exec pod -- mysql`
                }
                if passwordUpperPPrograms.contains(program) {
                    upperPIsPassword = true
                    optionsEnded = false
                }
            }
            if optionsEnded {
                result.append(leaf(argument))
                continue
            }
            if argument == "--" {
                result.append(argument)
                redactNext = false
                optionsEnded = true
                continue
            }

            if userPairNext {
                userPairNext = false
                if let redacted = redactingUserPassword(argument) {
                    result.append(redacted)
                    continue
                }
            }
            let lowered = argument.lowercased()
            let flag = lowered.split(
                separator: "=",
                maxSplits: 1,
                omittingEmptySubsequences: false
            ).first.map(String.init) ?? lowered
            let isSensitiveFlag = sensitiveArgumentFlags.contains(flag)

            if redactNext, !isSensitiveFlag {
                redactNext = false
                // An option after a password `-p` is the next option, not the
                // value: `mysql -p -u root` prompts for the password.
                if !(redactNextIsPasswordP && argument.hasPrefix("-")) {
                    result.append("[REDACTED]")
                    continue
                }
            }

            // `-p` / `-P` take a password only for the programs above. For
            // everything else they are a port (ssh, nc, docker), a pid (lsof),
            // parents (mkdir) or a find predicate (-perm, -print), which the
            // stored command line keeps for hunting.
            if !argument.hasPrefix("--"),
               (lowerPIsPassword && argument.hasPrefix("-p"))
                || (upperPIsPassword && argument.hasPrefix("-P")) {
                if argument.count > 2 {
                    result.append("\(argument.prefix(2))[REDACTED]")
                } else {
                    result.append(argument)
                    redactNext = true
                    redactNextIsPasswordP = true
                }
                continue
            }
            if userPairFlags.contains(lowered) {
                result.append(argument)
                userPairNext = true
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
                    redactNextIsPasswordP = false
                }
                continue
            }
            result.append(leaf(argument))
            redactNext = false
        }
        return result
    }

    /// The stored command line must be at least as redacted as argv. The ES
    /// collector builds it as argv joined by spaces; that form is rebuilt from
    /// the redacted arguments, so a flag and its value in separate tokens
    /// (`sshpass -p VALUE`) are redacted as argv redacts them.
    static func sanitize(commandLine: String, arguments: [String]) -> String {
        guard !arguments.isEmpty,
              commandLine == arguments.joined(separator: " ") else {
            return sanitize(commandLine)
        }
        return sanitize(sanitize(arguments: arguments).joined(separator: " "))
    }

    private static let userPairFlags: Set<String> = ["-u", "--user", "--proxy-user"]

    /// Programs whose `-p` takes a password, separated (`sshpass -p VALUE`,
    /// `mongosh -p VALUE`) or compact (`mysql -pVALUE`, `7z a -pVALUE`).
    private static let passwordLowerPPrograms: Set<String> = [
        "mysql", "mysqladmin", "mysqldump", "mysqlimport", "mysqlshow",
        "mysqlcheck", "mysqlpump", "mysqlsh", "mysqlbinlog", "mysqlslap",
        "mariadb", "mariadb-admin", "mariadb-dump", "mariadb-import",
        "mariadb-show", "mariadb-check", "mariadb-binlog",
        "sshpass", "mongo", "mongosh", "mongodump", "mongorestore",
        "mongoexport", "mongoimport", "mongofiles", "mongostat", "mongotop",
        "7z", "7za", "7zr", "7zz", "rar", "unrar",
    ]

    /// Programs whose `-P` takes a password (`zip -P VALUE`).
    private static let passwordUpperPPrograms: Set<String> = ["zip", "unzip", "zipcloak"]

    /// Lowercased basename of an argv token.
    private static func programName(_ token: String) -> String {
        let base = token.lastIndex(of: "/").map { token[token.index(after: $0)...] } ?? token[...]
        return base.lowercased()
    }

    /// `alice:secret` -> `alice:[REDACTED]`; nil when the token is not a
    /// `user:password` pair: no colon, or a numeric uid:gid (`501:20`). A
    /// numeric password after a named user (`admin:123456`) is redacted.
    private static func redactingUserPassword(_ value: String) -> String? {
        guard let colon = value.firstIndex(of: ":") else { return nil }
        let user = value[..<colon]
        let remainder = value[value.index(after: colon)...]
        guard !remainder.isEmpty else { return nil }
        if !user.isEmpty, user.allSatisfy(\.isASCIIDigit), remainder.allSatisfy(\.isASCIIDigit) {
            return nil
        }
        return "\(value[...colon])[REDACTED]"
    }
}

private extension Character {
    var isASCIIDigit: Bool { isASCII && isNumber }
}
