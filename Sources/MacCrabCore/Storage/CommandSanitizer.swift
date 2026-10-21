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

    /// URLs with embedded credentials: `://user:pass@host`. The spans are
    /// possessive and the password stops at `/`, which ends the authority,
    /// so each `://` scans only up to the next one instead of backtracking
    /// across the whole token.
    private static let urlCredentials = try! NSRegularExpression(
        pattern: #"(://[^:@/\s]++:)([^@\s/]++)(@)"#,
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
    /// chars that include mixed case, digits, and/or `+/=`). The separator is
    /// matched possessively: `\s*[=\s]\s*` backtracked quadratically over a
    /// long whitespace run.
    private static let base64AfterFlag = try! NSRegularExpression(
        pattern: #"(--(password|secret|token|key|auth|credential)(?:\s*+=\s*+|\s++))([A-Za-z0-9+/]{20,}={0,2})"#,
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

        // 5b. Password programs' `-p`, `-P` and `-N` values, then
        //     pair-specific passwords
        result = redactingFlagValues(in: result)
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
        zip(arguments, argumentActions(arguments, failClosed: true)).map { argument, action in
            switch action {
            case .keep: return leaf(argument)
            case .replace(let replacement): return replacement
            }
        }
    }

    /// What the walk does with one token.
    private enum ArgumentAction {
        /// Kept; argv still passes it through the per-token redactors.
        case keep
        /// Replaced: a value, or a flag with its attached value.
        case replace(String)
    }

    /// One decision per token, shared by argv and by the token walk over
    /// bare strings.
    ///
    /// In argv (`failClosed`) a `-p`/`-P` value is redacted unless argv[0] is
    /// a program whose flag is known not to carry a secret there (a port, pid,
    /// path or boolean). That list fails closed: an unknown program, a
    /// launcher or interpreter (`sudo`, `xargs`, `sh`, `python3`), the argv
    /// after `--` or a find `-exec`, and an ssh or docker command after its
    /// target get no exemption, because another program's arguments follow
    /// there. Strings redact only a password program's values: the same
    /// redactor runs on free text, which stays byte exact unless it carries a
    /// credential.
    private static func argumentActions(_ arguments: [String], failClosed: Bool) -> [ArgumentAction] {
        var actions: [ArgumentAction] = []
        actions.reserveCapacity(arguments.count)
        var redactNext = false
        // The pending value follows an optional-value `-p` (`mysql -p -u root`
        // prompts), so a dash token is the next option, not the value.
        var pendingValueIsOptional = false
        var userPairNext = false
        let program = arguments.first.map(programName) ?? ""
        var exemptionsApply = true
        let window = optionWindows[program]
        var windowValuePending = false
        var windowPositionals = 0
        // Whether a program seen so far takes a password through `-p` or `-P`.
        // A wrapper (`sudo`, `docker exec db`) puts it after argv[0].
        var lowerPIsPassword = false
        var lowerPIsOptional = false
        var lowerPBundles = false
        var upperPIsPassword = false
        var newPassphraseFlag = false
        let containerTool = containerLoginPrograms.contains(program)
        // find's operands before `-exec` are paths, not programs: `find
        // /x/security -print` names no password program.
        var operandsMayBePrograms = program != "find"

        for (index, argument) in arguments.enumerated() {
            if operandsMayBePrograms, !argument.hasPrefix("-"), !redactNext, !userPairNext {
                let name = programName(argument)
                if passwordLowerPPrograms.contains(name) {
                    lowerPIsPassword = true
                    // The most recent password program decides: in `docker exec
                    // mysql sshpass -p -Secret1` the dash token is sshpass's
                    // password, not the next option of a prompting mysql.
                    lowerPIsOptional = optionalValuePasswordPrograms.contains(name)
                    // 7z and rar switches never bundle; `-ssp` and `-ep` end in p.
                    lowerPBundles = !attachedOnlyPasswordPrograms.contains(name)
                }
                if passwordUpperPPrograms.contains(name) { upperPIsPassword = true }
                if name == "ssh-keygen" { newPassphraseFlag = true }
                if containerTool, argument == "login" {
                    lowerPIsPassword = true
                    lowerPIsOptional = false
                    lowerPBundles = true
                }
            }
            // An ssh destination or docker image ends the program's own
            // options; the remote or container command follows it.
            if exemptionsApply, index > 0, let window {
                if windowValuePending {
                    windowValuePending = false
                } else if argument.hasPrefix("--") {
                    windowValuePending = window.longValueOptions.contains(argument)
                } else if argument.hasPrefix("-"), argument.count > 1 {
                    windowValuePending = takesSeparateValue(argument, letters: window.valueLetters)
                } else if windowPositionals < window.leadingPositionals {
                    windowPositionals += 1
                } else {
                    exemptionsApply = false
                }
            }
            if argument == "--" {
                actions.append(.keep)
                redactNext = false
                exemptionsApply = false
                continue
            }

            if userPairNext {
                userPairNext = false
                if let redacted = redactingUserPassword(argument) {
                    actions.append(.replace(redacted))
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
            var letters: Set<Character> = []
            if lowerPIsPassword, lowerPBundles { letters.insert("p") }
            if upperPIsPassword { letters.insert("P") }
            if newPassphraseFlag { letters.insert("N") }
            let letterEnd = passwordLetterEnd(argument, letters: letters)

            if redactNext {
                redactNext = false
                // A flag handled here is the next option, not the pending
                // value (`curl -p -u alice:secret`), as is any option after an
                // optional-value `-p`. Anything else is the value, even a
                // dash-leading one (`zip -P -x7Kq9!`).
                let nextOption = isSensitiveFlag
                    || userPairFlags.contains(lowered)
                    || argument == "-p" || argument == "-P"
                    || letterEnd == argument.endIndex
                    || (pendingValueIsOptional && argument.hasPrefix("-"))
                if !nextOption {
                    actions.append(.replace("[REDACTED]"))
                    continue
                }
            }

            if !argument.hasPrefix("--"),
               argument.hasPrefix("-p") || argument.hasPrefix("-P") {
                let upper = argument.hasPrefix("-P")
                let passwordFlag = upper ? upperPIsPassword : lowerPIsPassword
                let exempt = failClosed
                    ? exemptionsApply && !passwordFlag
                        && (upper ? nonSecretUpperPPrograms : nonSecretLowerPPrograms).contains(program)
                    : !passwordFlag
                if exempt {
                    actions.append(.keep)
                    continue
                }
                if argument.count > 2 {
                    actions.append(.replace("\(argument.prefix(2))[REDACTED]"))
                } else {
                    actions.append(.keep)
                    redactNext = true
                    pendingValueIsOptional = !upper && lowerPIsOptional
                }
                continue
            }
            // A password program's letter ending a bundle, or ssh-keygen's new
            // passphrase: `zip -r9P VALUE`, `ssh-keygen -qN VALUE` take the next
            // token, `-NVALUE` carries it.
            if let letterEnd {
                if letterEnd == argument.endIndex {
                    actions.append(.keep)
                    redactNext = true
                    pendingValueIsOptional = false
                } else {
                    actions.append(.replace("\(argument[..<letterEnd])[REDACTED]"))
                }
                continue
            }
            if userPairFlags.contains(lowered) {
                actions.append(.keep)
                userPairNext = true
                redactNext = false
                continue
            }

            if isSensitiveFlag {
                if argument.contains("=") {
                    let originalFlag = argument.prefix {
                        $0 != "="
                    }
                    actions.append(.replace("\(originalFlag)=[REDACTED]"))
                    redactNext = false
                } else {
                    // A repeated sensitive flag is still a flag, not the prior
                    // flag's value. The final flag consumes the next ordinary
                    // token, preserving deterministic option structure.
                    actions.append(.keep)
                    redactNext = true
                    pendingValueIsOptional = false
                }
                continue
            }
            if program == "find", findCommandFlags.contains(argument) {
                exemptionsApply = false
                operandsMayBePrograms = true
            }
            actions.append(.keep)
            redactNext = false
        }
        return actions
    }

    /// A password program's `-p`, `-P` and `-N` values in a bare string (a
    /// shell `-c` script, a command line not captured as argv, free text),
    /// decided by the argv walk with each segment's first word as its
    /// program. One pass splits unquoted shell separators and quote-aware
    /// words, and only redacted words are rewritten, so the cost is linear in
    /// the input. A regex keyed on a program word and a later flag backtracked
    /// over every occurrence of the word, and matched it inside other words.
    static func redactingFlagValues(in text: String) -> String {
        guard containsSpaceDash(text.utf8) else { return text }
        let bytes = Array(text.utf8)
        var replacements: [(range: Range<Int>, with: String)] = []
        collectFlagValueRedactions(bytes, in: 0..<bytes.count, depth: 0, into: &replacements)
        guard !replacements.isEmpty else { return text }
        // A quoted script redacted inside a word that is itself replaced
        // gives way to the outer replacement.
        replacements.sort {
            $0.range.lowerBound != $1.range.lowerBound
                ? $0.range.lowerBound < $1.range.lowerBound
                : $0.range.upperBound > $1.range.upperBound
        }
        var output: [UInt8] = []
        output.reserveCapacity(bytes.count + 12 * replacements.count)
        var cursor = 0
        for replacement in replacements where replacement.range.lowerBound >= cursor {
            output.append(contentsOf: bytes[cursor..<replacement.range.lowerBound])
            output.append(contentsOf: replacement.with.utf8)
            cursor = replacement.range.upperBound
        }
        output.append(contentsOf: bytes[cursor...])
        return String(decoding: output, as: UTF8.self)
    }

    /// Quoted scripts nest (`sh -c 'security … -p VALUE'`); each level needs
    /// another layer of escapes, so a small bound covers real input.
    private static let maximumQuoteDepth = 3

    private static func collectFlagValueRedactions(
        _ bytes: [UInt8],
        in bounds: Range<Int>,
        depth: Int,
        into replacements: inout [(range: Range<Int>, with: String)]
    ) {
        var words: [(range: Range<Int>, text: String)] = []
        var quotedScripts: [Range<Int>] = []
        func endSegment() {
            if words.count > 1 {
                for (word, action) in zip(words, argumentActions(words.map(\.text), failClosed: false)) {
                    // Earlier patterns' output is already redacted.
                    guard case .replace(let replacement) = action,
                          !word.text.contains("[REDACTED]") else { continue }
                    replacements.append((word.range, replacement))
                }
            }
            words.removeAll(keepingCapacity: true)
        }
        var index = bounds.lowerBound
        while index < bounds.upperBound {
            if isSegmentSeparator(bytes[index]) {
                endSegment()
                index += 1
                continue
            }
            if isWordSpace(bytes[index]) {
                index += 1
                continue
            }
            let start = index
            var word: [UInt8] = []
            while index < bounds.upperBound,
                  !isSegmentSeparator(bytes[index]), !isWordSpace(bytes[index]) {
                let byte = bytes[index]
                if byte == UInt8(ascii: "'") || byte == UInt8(ascii: "\"") {
                    // A quoted span may hold spaces and separators; an
                    // unterminated one runs to the end.
                    index += 1
                    let content = index
                    var holdsSpace = false
                    while index < bounds.upperBound, bytes[index] != byte {
                        if byte == UInt8(ascii: "\""), bytes[index] == UInt8(ascii: "\\"),
                           index + 1 < bounds.upperBound {
                            index += 1
                        }
                        holdsSpace = holdsSpace || isWordSpace(bytes[index])
                        word.append(bytes[index])
                        index += 1
                    }
                    if holdsSpace { quotedScripts.append(content..<min(index, bounds.upperBound)) }
                    index += 1
                } else if byte == UInt8(ascii: "\\"), index + 1 < bounds.upperBound {
                    word.append(bytes[index + 1])
                    index += 2
                } else {
                    word.append(byte)
                    index += 1
                }
            }
            words.append((start..<min(index, bounds.upperBound), String(decoding: word, as: UTF8.self)))
        }
        endSegment()
        guard depth < maximumQuoteDepth else { return }
        for script in quotedScripts where containsSpaceDash(bytes[script]) {
            collectFlagValueRedactions(bytes, in: script, depth: depth + 1, into: &replacements)
        }
    }

    /// Every flag after a segment's first word follows a space or a tab.
    private static func containsSpaceDash<Bytes: Sequence>(_ bytes: Bytes) -> Bool where Bytes.Element == UInt8 {
        var afterSpace = false
        for byte in bytes {
            if afterSpace, byte == UInt8(ascii: "-") { return true }
            afterSpace = isWordSpace(byte)
        }
        return false
    }

    private static func isWordSpace(_ byte: UInt8) -> Bool {
        byte == UInt8(ascii: " ") || byte == UInt8(ascii: "\t") || byte == UInt8(ascii: "\r")
    }

    private static func isSegmentSeparator(_ byte: UInt8) -> Bool {
        byte == UInt8(ascii: ";") || byte == UInt8(ascii: "&")
            || byte == UInt8(ascii: "|") || byte == UInt8(ascii: "\n")
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

    private static let mysqlFamily: Set<String> = [
        "mysql", "mysqladmin", "mysqldump", "mysqlimport", "mysqlshow",
        "mysqlcheck", "mysqlpump", "mysqlsh", "mysqlbinlog", "mysqlslap",
        "mysql_upgrade", "mysql_secure_installation",
        "mariadb", "mariadb-admin", "mariadb-dump", "mariadb-import",
        "mariadb-show", "mariadb-check", "mariadb-binlog", "mariadb-upgrade",
        "mariadb-backup", "mariabackup",
    ]

    /// Programs whose `-p` value is optional or attached: `mysql -p -u root`
    /// and `mongosh -p` prompt, `7z a -pVALUE` never separates.
    private static let optionalValuePasswordPrograms: Set<String> = mysqlFamily.union([
        "mongo", "mongosh", "mongodump", "mongorestore", "mongoexport",
        "mongoimport", "mongofiles", "mongostat", "mongotop",
        "7z", "7za", "7zr", "7zz", "rar", "unrar",
    ])

    /// Programs whose switches never bundle: only a leading `-p` is theirs.
    private static let attachedOnlyPasswordPrograms: Set<String> = [
        "7z", "7za", "7zr", "7zz", "rar", "unrar",
    ]

    /// Programs whose `-p` takes a password, separated (`sshpass -p VALUE`,
    /// `security unlock-keychain -p VALUE`) or compact (`mysql -pVALUE`). Any
    /// of them in argv turns redaction on, through wrappers too.
    private static let passwordLowerPPrograms: Set<String> = optionalValuePasswordPrograms.union([
        "sshpass", "security", "altool", "cqlsh", "cypher-shell", "unar", "lsar",
    ])

    /// Programs whose `-P` takes a password (`zip -P VALUE`, `security import
    /// x.p12 -P VALUE`, `ssh-keygen -P OLD`) or secret-bearing properties
    /// (`gradle -Psigning.password=VALUE`).
    private static let passwordUpperPPrograms: Set<String> = [
        "zip", "unzip", "zipcloak", "security", "ssh-keygen", "sqlcmd", "bcp",
        "ipmitool", "mosquitto_pub", "mosquitto_sub", "mosquitto_rr",
        "gradle", "gradlew",
    ]

    /// `docker login -u USER -p VALUE` and the same for other registry clients.
    private static let containerLoginPrograms: Set<String> = [
        "docker", "podman", "nerdctl", "buildah", "skopeo", "oras", "helm", "finch",
    ]

    /// argv[0] programs whose `-p` is a port, pid, path, boolean or strip
    /// count, kept for hunting. Launchers, interpreters, and programs that run
    /// another program's argv without a `--` (`swift run`, `go run`, `gdb
    /// --args`, `kubectl patch -p`) stay off this list.
    private static let nonSecretLowerPPrograms: Set<String> = [
        "ssh", "autossh", "mosh", "scp", "sftp", "rsync", "nc", "ncat", "netcat",
        "telnet", "traceroute", "traceroute6", "dig", "nmap", "ping", "ping6",
        "redis-cli", "psql", "pg_dump", "pg_dumpall", "pg_restore", "pg_isready",
        "pg_basebackup", "createdb", "dropdb", "createuser", "dropuser",
        "vacuumdb", "reindexdb", "clusterdb", "pgbench",
        "lsof", "ps", "top", "renice", "lldb", "dtrace", "sample",
        "spindump", "leaks", "heap", "vmmap", "footprint",
        "mkdir", "cp", "install", "tar", "bsdtar", "gtar", "cpio", "patch",
        "git", "diff", "ls", "find", "ssh-keygen",
        "docker", "podman", "nerdctl",
        "cc", "c++", "clang", "clang++", "gcc", "g++", "ld", "ld64",
        "swiftc", "swift-frontend", "swift-build", "swift-test",
        "xcodebuild", "rustc", "cargo", "make", "gmake",
    ]

    /// argv[0] programs whose `-P` is a port, pid, path, boolean or name.
    private static let nonSecretUpperPPrograms: Set<String> = mysqlFamily.union([
        "scp", "sftp", "ssh", "rsync", "lsof", "pgrep", "pkill", "grep", "egrep",
        "fgrep", "rg", "cp", "ln", "find", "chown", "chmod", "chgrp", "du", "pwd",
        "rm", "tar", "bsdtar", "gtar", "curl", "wget", "mvn", "cc", "c++",
        "clang", "clang++", "gcc", "g++", "cpp", "cmake", "docker", "podman",
        "nerdctl", "nc",
    ])

    /// find runs another program's argv after these.
    private static let findCommandFlags: Set<String> = ["-exec", "-execdir", "-ok", "-okdir"]

    /// The options a program takes before its target, and how many positionals
    /// (a subcommand) precede that target.
    private struct OptionWindow {
        let valueLetters: Set<Character>
        let longValueOptions: Set<String>
        let leadingPositionals: Int
    }

    private static let containerWindow = OptionWindow(
        valueLetters: Set("acehlmpuvw"),
        longValueOptions: [
            "--name", "--network", "--net", "--env", "--env-file", "--volume",
            "--mount", "--label", "--user", "--workdir", "--entrypoint",
            "--platform", "--hostname", "--memory", "--cpus", "--restart",
            "--pull", "--publish", "--expose", "--device", "--add-host",
            "--log-driver", "--log-opt", "--dns", "--cap-add", "--cap-drop",
            "--security-opt", "--tmpfs", "--ulimit", "--gpus", "--runtime",
            "--shm-size", "--ip", "--pid", "--ipc", "--cidfile", "--health-cmd",
            "--stop-signal", "--stop-timeout",
        ],
        leadingPositionals: 1
    )

    /// ssh-style destinations and container images end the program's own
    /// options. An unknown long option counts as boolean, so a mistake ends
    /// the exemption early rather than late.
    private static let optionWindows: [String: OptionWindow] = [
        "ssh": OptionWindow(valueLetters: Set("bBcDeEFiIJlLmoOpPQRSwW"), longValueOptions: [], leadingPositionals: 0),
        "autossh": OptionWindow(valueLetters: Set("bBcDeEFiIJlLmMoOpPQRSwW"), longValueOptions: [], leadingPositionals: 0),
        "mosh": OptionWindow(valueLetters: Set("p"), longValueOptions: [], leadingPositionals: 0),
        "docker": containerWindow,
        "podman": containerWindow,
        "nerdctl": containerWindow,
    ]

    /// Whether a one-dash option token takes the next token as its value: the
    /// first value-taking letter in the bundle is its last letter.
    private static func takesSeparateValue(_ token: String, letters: Set<Character>) -> Bool {
        let flags = token.dropFirst()
        guard let first = flags.firstIndex(where: { letters.contains($0) }) else { return false }
        return flags.index(after: first) == flags.endIndex
    }

    /// The end of a password letter that ends a one-dash bundle of letters
    /// and digits (`-erP`, `-r9P`, `-qN`), whose value is the next token, or
    /// of a compact `-NVALUE`. `-p`/`-P` compact forms are handled earlier.
    private static func passwordLetterEnd(_ token: String, letters: Set<Character>) -> String.Index? {
        guard !letters.isEmpty, token.hasPrefix("-"), !token.hasPrefix("--") else { return nil }
        let flags = token.dropFirst()
        if flags.count > 1, flags.first == "N", letters.contains("N") {
            return flags.index(after: flags.startIndex)
        }
        guard let last = flags.last, letters.contains(last),
              flags.allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber) }) else { return nil }
        return flags.endIndex
    }

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
