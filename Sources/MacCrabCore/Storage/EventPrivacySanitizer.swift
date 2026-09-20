import Foundation

public enum EventPrivacySanitizerError: Error, Sendable, Equatable {
    case invalidEventIdentity
    case invalidSanitizedJSONObject
}

/// One recursive privacy boundary shared by the canonical event journal,
/// sparse projection, alert triggering JSON, and alert-owned evidence.
///
/// Sanitizing only `commandLine` is insufficient: argv, environment values,
/// enrichment keys/values, and free-form rule text can all carry credentials.
/// This implementation rebuilds the typed Event directly and encodes exactly
/// once. It deliberately does not construct a JSONSerialization mirror graph
/// or decode a second Event: those transient copies made a maximum accepted
/// record incompatible with the process memory envelope. The policy is for
/// credentials at rest, not external telemetry privacy: private addresses,
/// hostnames, hashes, paths, certificate identifiers, and opaque forensic
/// fields remain intact unless they sit under an explicitly sensitive dynamic
/// map key.
public enum EventPrivacySanitizer {
    /// Cheap gate in front of the command/vendor regex suites. Ordinary event
    /// strings (paths, process names, IPs, hashes) dominate the hot path and do
    /// not warrant dozens of `NSRegularExpression` scans each.
    private static let credentialHints = [
        "password", "passwd", "secret", "token", "credential",
        "bearer", "authorization", "api-key", "api_key", "apikey",
        "access-key", "access_key", "private-key", "private_key",
        // Candidate markers must allow the redactors' whitespace, assignment
        // suffixes and embedded quoted MySQL forms. Regexes decide redaction.
        "key", "auth", "://", "-p", "sk-", "aiza", "akia",
        "asia", "agpa", "aida", "aroa", "aipa", "anpa", "anva",
        "asca", "ghp_", "gho_", "ghu_", "ghs_", "ghr_",
        "github_pat_", "xoxa-", "xoxb-", "xoxo-", "xoxp-",
        "xoxr-", "xoxs-", "npm_", "pmak-", "whsec_", "sg.",
        "key-", "cf", "dop_v1_", "hrku-", "vrcl_", "vercel_",
        "eyj",
        // Deliberate policy expansion: the existing Stripe redactor accepts
        // these underscore prefixes, which the earlier "sk-" hint missed.
        "sk_live_", "sk_test_", "pk_live_", "pk_test_", "rk_live_", "rk_test_",
    ]

    private static let asciiCredentialHints = ASCIIMatcher(credentialHints)
    private static let asciiShortCredentialHints = ASCIIMatcher([
        "-p", "key", "auth", "://",
    ])
    private static let asciiSensitiveKeys = ASCIIMatcher([
        "password", "passwd", "secret", "token", "apikey", "authorization",
        "credential", "privatekey", "accesskey", "cookie",
    ])

    public struct Result: Sendable, Equatable {
        public let event: Event
        public let canonicalJSON: Data

        public init(event: Event, canonicalJSON: Data) {
            self.event = event
            self.canonicalJSON = canonicalJSON
        }
    }

    private static func makeEncoder() -> JSONEncoder {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return encoder
    }

    public static func sanitize(_ event: Event) throws -> Result {
        let sanitizedEvent = sanitizeEventFields(event)
        let canonicalJSON = try makeEncoder().encode(sanitizedEvent)
        return Result(
            event: sanitizedEvent,
            canonicalJSON: canonicalJSON
        )
    }

    /// Internal object form used by the bounded alert compactor so it never
    /// repeats or drifts from the journal sanitizer.
    static func sanitizedJSONObject(
        _ event: Event
    ) throws -> (object: Any, canonicalJSON: Data) {
        let sanitized = try sanitize(event)
        let object = try JSONSerialization.jsonObject(
            with: sanitized.canonicalJSON
        )
        guard JSONSerialization.isValidJSONObject(object) else {
            throw EventPrivacySanitizerError.invalidSanitizedJSONObject
        }
        return (object, sanitized.canonicalJSON)
    }

    static func canonicalJSONData(fromJSONObject object: Any) throws -> Data {
        try JSONSerialization.data(
            withJSONObject: object,
            options: [.sortedKeys, .withoutEscapingSlashes]
        )
    }

    private static func sanitizeEventFields(_ event: Event) -> Event {
        let process = event.process
        let safeProcess = ProcessInfo(
            pid: process.pid,
            ppid: process.ppid,
            rpid: process.rpid,
            name: process.name,
            executable: process.executable,
            commandLine: sanitizeString(process.commandLine),
            args: CommandSanitizer.sanitize(arguments: process.args).map(
                sanitizeString
            ),
            workingDirectory: process.workingDirectory,
            userId: process.userId,
            userName: process.userName,
            groupId: process.groupId,
            startTime: process.startTime,
            exitCode: process.exitCode,
            codeSignature: process.codeSignature,
            ancestors: process.ancestors,
            architecture: process.architecture,
            isPlatformBinary: process.isPlatformBinary,
            hashes: process.hashes,
            session: process.session,
            envVars: process.envVars.map(sanitizeDynamicMap),
            auditIdentity: process.auditIdentity
        )
        let safeMatches = sanitizeRuleMatches(event.ruleMatches)
        return Event(
            id: event.id,
            timestamp: event.timestamp,
            eventCategory: event.eventCategory,
            eventType: event.eventType,
            eventAction: event.eventAction,
            process: safeProcess,
            file: event.file,
            network: event.network,
            tcc: event.tcc,
            enrichments: sanitizeDynamicMap(event.enrichments),
            severity: event.severity,
            ruleMatches: safeMatches
        )
    }

    package static func sanitizeRuleMatches(
        _ matches: [RuleMatch]
    ) -> [RuleMatch] {
        matches.map { match in
            RuleMatch(
                ruleId: sanitizeString(match.ruleId),
                ruleName: sanitizeString(match.ruleName),
                severity: match.severity,
                description: sanitizeString(match.description),
                mitreTechniques: match.mitreTechniques.map(sanitizeString),
                tags: match.tags.map(sanitizeString),
                suppressible: match.suppressible
            )
        }
    }

    /// Dynamic maps are the only fields where the key itself defines whether
    /// an otherwise innocuous-looking value is secret. Sorted first-wins keeps
    /// collisions deterministic after a key is credential-shape sanitized.
    package static func sanitizeDynamicMap(
        _ source: [String: String]
    ) -> [String: String] {
        var result: [String: String] = [:]
        result.reserveCapacity(source.count)
        for key in source.keys.sorted() {
            guard let value = source[key] else { continue }
            let safeKey = sanitizeString(key)
            guard result[safeKey] == nil else { continue }
            result[safeKey] = isSensitiveKey(key)
                ? "[REDACTED]" : sanitizeString(value)
        }
        return result
    }

    static func sanitizeString(_ value: String) -> String {
        guard mayContainCredential(value) else { return value }
        return OTLPAttributeSanitizer.redactCredentialShapes(
            CommandSanitizer.sanitize(value)
        )
    }

    package static func mayContainCredential(_ value: String) -> Bool {
        let isLong = value.utf8.count >= 8
        let matcher = isLong ? asciiCredentialHints : asciiShortCredentialHints
        var state = 0
        var previous: UInt8 = 0
        var found = false
        for byte in value.utf8 {
            // Even after a match, inspect the remaining bytes: any Unicode
            // selects the original whole-string matching policy.
            guard byte < 128 else {
                return mayContainCredentialFallback(value)
            }
            if !found {
                state = matcher.next(state, lowercaseASCII(byte))
                found = matcher.terminal[state]
                    || (isLong && ((previous == 83 && byte == 75)
                        || (previous == 65 && byte == 67)))
            }
            previous = byte
        }
        return found
    }

    private static func mayContainCredentialFallback(_ value: String) -> Bool {
        // Short quoted assignments, MySQL options and URL fragments can
        // still contain credentials. Avoid scanning the full vendor list.
        guard value.utf8.count >= 8 else {
            let lowered = value.lowercased()
            return lowered.contains("-p") || lowered.contains("key")
                || lowered.contains("auth") || lowered.contains("://")
        }
        let lowered = value.lowercased()
        if value.utf8.allSatisfy({ $0 < 128 }) {
            // ASCII has no canonical-equivalence or grapheme boundaries to
            // resolve. Literal Foundation searches avoid repeatedly walking
            // Swift Substring indices for every hint in ordinary event fields.
            // Keep the original Unicode path below and leave both redactors
            // authoritative: a hint only decides whether they must run.
            let searchable = lowered as NSString
            let original = value as NSString
            return credentialHints.contains {
                searchable.range(of: $0, options: .literal).location != NSNotFound
            } || original.range(of: "SK", options: .literal).location != NSNotFound
                || original.range(of: "AC", options: .literal).location != NSNotFound
        }
        return credentialHints.contains { lowered.contains($0) }
            || lowered.hasPrefix("-p")
            || value.contains("SK") || value.contains("AC")
    }

    package static func isSensitiveKey(_ key: String) -> Bool {
        var state = 0
        var found = false
        for byte in key.utf8 {
            guard byte < 128 else { return isSensitiveKeyFallback(key) }
            if found { continue }
            let folded = lowercaseASCII(byte)
            // Match lowercased().filter(isLetter || isNumber) for ASCII
            // without constructing a normalized string or per-call buffer.
            if (folded >= 97 && folded <= 122)
                || (folded >= 48 && folded <= 57) {
                state = asciiSensitiveKeys.next(state, folded)
                found = asciiSensitiveKeys.terminal[state]
            }
        }
        return found
    }

    @inline(__always)
    private static func lowercaseASCII(_ byte: UInt8) -> UInt8 {
        byte >= 65 && byte <= 90 ? byte + 32 : byte
    }

    private static func isSensitiveKeyFallback(_ key: String) -> Bool {
        let normalized = key.lowercased().filter {
            $0.isLetter || $0.isNumber
        }
        return normalized.contains("password")
            || normalized.contains("passwd")
            || normalized.contains("secret")
            || normalized.contains("token")
            || normalized.contains("apikey")
            || normalized.contains("authorization")
            || normalized.contains("credential")
            || normalized.contains("privatekey")
            || normalized.contains("accesskey")
            || normalized.contains("cookie")
    }

    /// Immutable Aho-Corasick tables search all policy literals in one pass.
    /// Their size depends only on the fixed patterns above (84,039 bytes of
    /// retained table payload), never on event contents. Construction runs
    /// once per static matcher; searches need no normalization buffer or
    /// input-dependent cache. String's UTF-8 access may still bridge storage.
    private struct ASCIIMatcher: Sendable {
        let transitions: [UInt16]
        let terminal: [Bool]

        init(_ patterns: [String]) {
            var rows = [[Int]](
                repeating: [Int](repeating: -1, count: 128), count: 1
            )
            var accepting = [false]
            for pattern in patterns {
                var node = 0
                precondition(!pattern.isEmpty)
                for byte in pattern.utf8 {
                    precondition(byte < 128)
                    if rows[node][Int(byte)] == -1 {
                        rows[node][Int(byte)] = rows.count
                        rows.append([Int](repeating: -1, count: 128))
                        accepting.append(false)
                    }
                    node = rows[node][Int(byte)]
                }
                accepting[node] = true
            }
            precondition(rows.count <= Int(UInt16.max))
            var failures = [Int](repeating: 0, count: rows.count)
            var queue: [Int] = []
            for byte in 0..<128 {
                if rows[0][byte] == -1 {
                    rows[0][byte] = 0
                } else {
                    queue.append(rows[0][byte])
                }
            }
            var head = 0
            while head < queue.count {
                let node = queue[head]
                head += 1
                for byte in 0..<128 {
                    let child = rows[node][byte]
                    if child == -1 {
                        rows[node][byte] = rows[failures[node]][byte]
                    } else {
                        let failure = rows[failures[node]][byte]
                        failures[child] = failure
                        accepting[child] = accepting[child] || accepting[failure]
                        queue.append(child)
                    }
                }
            }
            transitions = rows.flatMap { $0.map(UInt16.init) }
            terminal = accepting
        }

        @inline(__always)
        func next(_ state: Int, _ byte: UInt8) -> Int {
            Int(transitions[state * 128 + Int(byte)])
        }
    }
}
