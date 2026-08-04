// ThreatHunter.swift
// MacCrabCore
//
// Translates natural language threat hunting queries into database searches.
// Enables security analysts to query events and alerts using plain English.
// Uses deterministic patterns with optional LLM enhancement.

import Foundation
import CSQLCipher
import os.log

enum ThreatHuntQueryStore: Sendable, Equatable {
    case events
    case alerts
}

enum ThreatHuntSQLRejection: Sendable, Equatable {
    case empty
    case tooLong
    case malformed
    case notSelect
    case multipleStatements
    case forbiddenOperation
    case recursive
    case crossStore
    case invalidLimit
    case rowLimitExceeded
    case offsetLimitExceeded
}

enum ThreatHuntSQLValidation: Sendable, Equatable {
    case accepted(ThreatHuntQueryStore)
    case rejected(ThreatHuntSQLRejection)
}

/// One production policy for every deterministic and LLM-generated hunt query.
/// Tests call this exact validator through `@testable`; there is intentionally no
/// test-side copy of the SQL rules.
enum ThreatHuntSQLPolicy {
    static let maximumSQLBytes = 2_000
    static let maximumRows = 500
    static let maximumOffset = 100_000

    static func validate(_ sql: String) -> ThreatHuntSQLValidation {
        guard !sql.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            return .rejected(.empty)
        }
        guard sql.utf8.count <= maximumSQLBytes else {
            return .rejected(.tooLong)
        }
        guard let tokens = tokenize(sql), !tokens.isEmpty else {
            return .rejected(.malformed)
        }
        guard tokens[0] == "SELECT" else {
            return .rejected(.notSelect)
        }
        guard !tokens.contains(";") else {
            return .rejected(.multipleStatements)
        }

        let forbidden: Set<String> = [
            "DELETE", "UPDATE", "INSERT", "DROP", "ALTER", "CREATE",
            "ATTACH", "DETACH", "PRAGMA", "VACUUM", "ANALYZE",
            "REINDEX", "REPLACE", "SAVEPOINT", "RELEASE", "ROLLBACK",
            "BEGIN", "COMMIT", "GRANT", "REVOKE",
        ]
        guard forbidden.isDisjoint(with: tokens) else {
            return .rejected(.forbiddenOperation)
        }
        // Common table expressions are unnecessary for the supported hunt
        // schema. Rejecting WITH entirely closes recursive CTE expansion even
        // when RECURSIVE is omitted or hidden inside a subquery.
        guard !tokens.contains("WITH"), !tokens.contains("RECURSIVE") else {
            return .rejected(.recursive)
        }

        var index = 0
        while index < tokens.count {
            guard tokens[index] == "LIMIT" else {
                index += 1
                continue
            }
            guard index + 1 < tokens.count,
                  let first = Int(tokens[index + 1]), first >= 0 else {
                return .rejected(.invalidLimit)
            }

            if index + 2 < tokens.count, tokens[index + 2] == "," {
                guard index + 3 < tokens.count,
                      let count = Int(tokens[index + 3]), count >= 0 else {
                    return .rejected(.invalidLimit)
                }
                guard first <= maximumOffset else {
                    return .rejected(.offsetLimitExceeded)
                }
                guard count <= maximumRows else {
                    return .rejected(.rowLimitExceeded)
                }
                index += 4
                continue
            }

            guard first <= maximumRows else {
                return .rejected(.rowLimitExceeded)
            }
            if index + 2 < tokens.count, tokens[index + 2] == "OFFSET" {
                guard index + 3 < tokens.count,
                      let offset = Int(tokens[index + 3]), offset >= 0 else {
                    return .rejected(.invalidLimit)
                }
                guard offset <= maximumOffset else {
                    return .rejected(.offsetLimitExceeded)
                }
                index += 4
                continue
            }
            // LIMIT expressions can turn a superficially small literal into an
            // unbounded result (for example LIMIT 1+999999). Only a literal at
            // the end of the statement/subquery is accepted.
            if index + 2 < tokens.count,
               tokens[index + 2] != ")" {
                return .rejected(.invalidLimit)
            }
            index += 2
        }

        let referencesEvents = tokens.contains("EVENTS")
            || tokens.contains("EVENTS_FTS")
        let referencesAlerts = tokens.contains("ALERTS")
        guard !(referencesEvents && referencesAlerts) else {
            return .rejected(.crossStore)
        }
        return .accepted(referencesAlerts ? .alerts : .events)
    }

    /// Small SQL lexer that ignores quoted values and comments. It exists to
    /// make keyword/table classification insensitive to strings such as
    /// `process_name = 'alerts'`; SQLite's authorizer remains the final parser-
    /// aware enforcement layer at prepare time.
    private static func tokenize(_ sql: String) -> [String]? {
        let bytes = Array(sql.utf8)
        var tokens: [String] = []
        var index = 0

        while index < bytes.count {
            let byte = bytes[index]
            if byte == 9 || byte == 10 || byte == 13 || byte == 32 {
                index += 1
                continue
            }

            if byte == 45, index + 1 < bytes.count, bytes[index + 1] == 45 {
                index += 2
                while index < bytes.count, bytes[index] != 10 { index += 1 }
                continue
            }
            if byte == 47, index + 1 < bytes.count, bytes[index + 1] == 42 {
                index += 2
                var closed = false
                while index + 1 < bytes.count {
                    if bytes[index] == 42, bytes[index + 1] == 47 {
                        index += 2
                        closed = true
                        break
                    }
                    index += 1
                }
                guard closed else { return nil }
                continue
            }

            if byte == 39 {
                index += 1
                var closed = false
                while index < bytes.count {
                    if bytes[index] == 39 {
                        if index + 1 < bytes.count, bytes[index + 1] == 39 {
                            index += 2
                        } else {
                            index += 1
                            closed = true
                            break
                        }
                    } else {
                        index += 1
                    }
                }
                guard closed else { return nil }
                continue
            }

            if byte == 34 || byte == 96 || byte == 91 {
                let closing: UInt8 = byte == 91 ? 93 : byte
                index += 1
                let start = index
                while index < bytes.count, bytes[index] != closing { index += 1 }
                guard index < bytes.count else { return nil }
                tokens.append(
                    String(decoding: bytes[start..<index], as: UTF8.self).uppercased()
                )
                index += 1
                continue
            }

            let isIdentifierStart = (byte >= 65 && byte <= 90)
                || (byte >= 97 && byte <= 122) || byte == 95
            if isIdentifierStart {
                let start = index
                index += 1
                while index < bytes.count {
                    let next = bytes[index]
                    let isIdentifierPart = (next >= 65 && next <= 90)
                        || (next >= 97 && next <= 122)
                        || (next >= 48 && next <= 57)
                        || next == 95 || next == 36
                    guard isIdentifierPart else { break }
                    index += 1
                }
                tokens.append(
                    String(decoding: bytes[start..<index], as: UTF8.self).uppercased()
                )
                continue
            }

            if byte >= 48 && byte <= 57 {
                let start = index
                index += 1
                while index < bytes.count, bytes[index] >= 48, bytes[index] <= 57 {
                    index += 1
                }
                tokens.append(String(decoding: bytes[start..<index], as: UTF8.self))
                continue
            }

            guard byte < 128 else { return nil }
            tokens.append(String(UnicodeScalar(byte)))
            index += 1
        }
        return tokens
    }
}

struct ThreatHuntExecutionLimits: Sendable {
    static let production = ThreatHuntExecutionLimits()

    let maxRows: Int
    let maxColumns: Int
    let maxCellBytes: Int
    let maxResultBytes: Int
    let deadlineMilliseconds: Int
    let progressSteps: Int32

    init(
        maxRows: Int = ThreatHuntSQLPolicy.maximumRows,
        maxColumns: Int = 64,
        maxCellBytes: Int = 4_096,
        maxResultBytes: Int = 512 * 1_024,
        deadlineMilliseconds: Int = 1_000,
        progressSteps: Int32 = 1_000
    ) {
        self.maxRows = max(1, min(maxRows, ThreatHuntSQLPolicy.maximumRows))
        self.maxColumns = max(1, min(maxColumns, 64))
        self.maxCellBytes = max(1, min(maxCellBytes, 4_096))
        self.maxResultBytes = max(1, min(maxResultBytes, 512 * 1_024))
        self.deadlineMilliseconds = max(1, min(deadlineMilliseconds, 2_000))
        self.progressSteps = max(1, min(progressSteps, 10_000))
    }
}

public enum ThreatHuntExecutionStatus: String, Sendable, Equatable {
    case completed
    case rowLimitReached
    case resultLimitReached
    case timedOut
    case rejected
    case databaseUnavailable
}

struct ThreatHuntSQLExecution: Sendable, Equatable {
    let rows: [[String: String]]
    let status: ThreatHuntExecutionStatus
}

private final class ThreatHuntDeadlineContext {
    let deadline: UInt64
    var interrupted = false

    init(milliseconds: Int) {
        deadline = DispatchTime.now().uptimeNanoseconds
            + UInt64(milliseconds) * 1_000_000
    }
}

private final class ThreatHuntAuthorizationContext {
    let store: ThreatHuntQueryStore

    init(store: ThreatHuntQueryStore) {
        self.store = store
    }
}

private let threatHuntProgressCallback: @convention(c) (UnsafeMutableRawPointer?) -> Int32 = {
    rawContext in
    guard let rawContext else { return 1 }
    let context = Unmanaged<ThreatHuntDeadlineContext>
        .fromOpaque(rawContext).takeUnretainedValue()
    if DispatchTime.now().uptimeNanoseconds >= context.deadline {
        context.interrupted = true
        return 1
    }
    return 0
}

private let threatHuntAuthorizerCallback: @convention(c) (
    UnsafeMutableRawPointer?, Int32, UnsafePointer<CChar>?,
    UnsafePointer<CChar>?, UnsafePointer<CChar>?, UnsafePointer<CChar>?
) -> Int32 = { rawContext, action, first, second, _, _ in
    guard let rawContext else { return SQLITE_DENY }
    let context = Unmanaged<ThreatHuntAuthorizationContext>
        .fromOpaque(rawContext).takeUnretainedValue()

    switch action {
    case SQLITE_SELECT:
        return SQLITE_OK
    case SQLITE_READ:
        guard let first else { return SQLITE_DENY }
        let table = String(cString: first).lowercased()
        switch context.store {
        case .events:
            return table == "events" || table == "events_fts"
                || table.hasPrefix("events_fts_") ? SQLITE_OK : SQLITE_DENY
        case .alerts:
            return table == "alerts" ? SQLITE_OK : SQLITE_DENY
        }
    case SQLITE_FUNCTION:
        guard let functionPointer = second ?? first else { return SQLITE_DENY }
        let function = String(cString: functionPointer).lowercased()
        let allowed: Set<String> = [
            "abs", "avg", "coalesce", "count", "date", "datetime", "glob",
            "ifnull", "instr", "julianday", "length", "like", "likelihood",
            "likely", "lower", "ltrim", "match", "max", "min", "nullif",
            "round", "rtrim", "sign", "strftime", "substr", "substring",
            "sum", "time", "total", "trim", "typeof", "unicode",
            "unixepoch", "unlikely", "upper",
        ]
        return allowed.contains(function) ? SQLITE_OK : SQLITE_DENY
    default:
        // Includes ATTACH, PRAGMA, writes, transactions, recursive SELECTs,
        // schema inspection, and extension/virtual-table management.
        return SQLITE_DENY
    }
}

/// Translates natural language threat hunting queries into database searches.
/// Enables security analysts to query events and alerts using plain English.
public actor ThreatHunter {
    private let logger = Logger(subsystem: "com.maccrab.detection", category: "threat-hunter")

    /// A hunt query result.
    public struct HuntResult: Sendable {
        public let query: String           // Original natural language query
        public let sqlQuery: String        // Generated SQL
        public let resultCount: Int
        public let results: [[String: String]]  // Rows as key-value maps
        public let executionTime: TimeInterval
        public let interpretation: String  // How the query was interpreted
        /// Non-completed states must never be presented as proof that no
        /// matching evidence exists. Limit states contain a partial result.
        public let status: ThreatHuntExecutionStatus
    }

    private let eventsDatabasePath: String
    private let alertsDatabasePath: String
    private let llmService: LLMService?
    private let limits: ThreatHuntExecutionLimits

    public init(
        eventsDatabasePath: String,
        alertsDatabasePath: String,
        llmService: LLMService? = nil
    ) {
        self.eventsDatabasePath = eventsDatabasePath
        self.alertsDatabasePath = alertsDatabasePath
        self.llmService = llmService
        self.limits = .production
    }

    /// Source-compatible convenience for callers that already pass events.db.
    /// Alert hunts are routed to the sibling alerts.db, never attached to the
    /// event connection.
    public init(databasePath: String, llmService: LLMService? = nil) {
        self.eventsDatabasePath = databasePath
        self.alertsDatabasePath = URL(fileURLWithPath: databasePath)
            .deletingLastPathComponent()
            .appendingPathComponent("alerts.db")
            .path
        self.llmService = llmService
        self.limits = .production
    }

    init(
        eventsDatabasePath: String,
        alertsDatabasePath: String,
        llmService: LLMService? = nil,
        limits: ThreatHuntExecutionLimits
    ) {
        self.eventsDatabasePath = eventsDatabasePath
        self.alertsDatabasePath = alertsDatabasePath
        self.llmService = llmService
        self.limits = limits
    }

    /// Execute a natural language threat hunting query.
    public func hunt(_ query: String) -> HuntResult? {
        let start = Date()

        // Normalize the query
        let normalized = query.lowercased().trimmingCharacters(in: .whitespacesAndNewlines)

        // Try to match against known query patterns
        guard let (sql, interpretation) = translateQuery(normalized) else {
            // No template matched — don't give up. The CLI markets NL hunting,
            // so a bare term must still search the stream (audit: hunt returned
            // 0 + suggestions while matching events plainly existed).
            if let (fbSQL, fbInterp) = substringFallback(normalized) {
                let execution = executeSQL(fbSQL)
                return HuntResult(
                    query: query, sqlQuery: fbSQL,
                    resultCount: execution.rows.count, results: execution.rows,
                    executionTime: Date().timeIntervalSince(start),
                    interpretation: fbInterp, status: execution.status
                )
            }
            return HuntResult(
                query: query, sqlQuery: "", resultCount: 0, results: [],
                executionTime: 0,
                interpretation: "Could not interpret query. Try: 'show alerts from last hour', 'find unsigned processes', 'network connections to unusual ports'",
                status: .rejected
            )
        }

        // Execute the SQL
        var execution = executeSQL(sql)
        var usedSQL = sql
        var usedInterp = interpretation

        // A specific keyword template can latch onto one term and return nothing
        // (e.g. "download" → the /Downloads/ template misses a curl exec that
        // lives elsewhere). If the template found nothing, widen to a substring
        // search across the raw query before reporting "no results". Widen only
        // a completed EVENT query: an alert hunt must never become unrelated
        // event rows, and timeout/unavailable/truncated is not an empty result.
        let initialStore: ThreatHuntQueryStore? = {
            if case .accepted(let store) = ThreatHuntSQLPolicy.validate(sql) {
                return store
            }
            return nil
        }()
        if execution.status == .completed,
           execution.rows.isEmpty,
           initialStore == .events,
           let (fbSQL, fbInterp) = substringFallback(normalized), fbSQL != sql {
            let widened = executeSQL(fbSQL)
            if widened.status == .completed, !widened.rows.isEmpty {
                execution = widened
                usedSQL = fbSQL
                usedInterp = "\(interpretation) — no matches; widened to substring search. \(fbInterp)"
            }
        }

        return HuntResult(
            query: query, sqlQuery: usedSQL, resultCount: execution.rows.count,
            results: execution.rows,
            executionTime: Date().timeIntervalSince(start),
            interpretation: usedInterp, status: execution.status
        )
    }

    /// Build a broad substring search across event columns from the query's
    /// significant terms (stopwords dropped). Used when no template matched or a
    /// template returned nothing, so `hunt "curl"` always searches the stream.
    private func substringFallback(_ query: String) -> (sql: String, interpretation: String)? {
        let stop: Set<String> = [
            "show", "find", "search", "get", "list", "me", "all", "the", "a", "an",
            "from", "with", "for", "of", "in", "on", "to", "and", "or", "that", "any",
            "events", "event", "alerts", "alert", "process", "processes",
        ]
        let terms = query.split(whereSeparator: { " \t\"',".contains($0) })
            .map(String.init)
            .filter { $0.count > 1 && !stop.contains($0) }
        guard !terms.isEmpty else { return nil }
        let clauses = terms.prefix(5).map { term -> String in
            let e = term.replacingOccurrences(of: "'", with: "''")
            return "(process_name LIKE '%\(e)%' OR process_path LIKE '%\(e)%' OR process_commandline LIKE '%\(e)%' OR file_path LIKE '%\(e)%' OR network_dest_ip LIKE '%\(e)%')"
        }
        let sql = "SELECT * FROM events WHERE \(clauses.joined(separator: " OR ")) ORDER BY timestamp DESC LIMIT 100"
        let shown = terms.prefix(5).map { "'\($0)'" }.joined(separator: ", ")
        return (sql, "Substring search for \(shown) across process and file columns")
    }

    /// Execute a threat hunting query with LLM enhancement.
    /// Falls back to deterministic pattern matching if LLM is unavailable.
    public func huntEnhanced(_ query: String) async -> HuntResult? {
        // Try LLM first
        if let llm = llmService {
            let start = Date()
            let semanticToken = await llm.beginDownstreamValidation(
                feature: .threatHunt
            )
            if let enhancement = await llm.query(
                systemPrompt: LLMPrompts.threatHuntSystem,
                userPrompt: LLMPrompts.threatHuntUser(query: query),
                maxTokens: 512, temperature: 0.1, useCache: false,
                feature: .threatHunt
            ) {
                let sql = enhancement.response.trimmingCharacters(in: .whitespacesAndNewlines)
                if case .accepted = ThreatHuntSQLPolicy.validate(sql) {
                    _ = await llm.finishDownstreamValidation(
                        token: semanticToken,
                        outcome: .accepted
                    )
                    let execution = executeSQL(sql)
                    let elapsed = Date().timeIntervalSince(start)
                    return HuntResult(
                        query: query, sqlQuery: sql,
                        resultCount: execution.rows.count,
                        results: execution.rows, executionTime: elapsed,
                        interpretation: "LLM-generated SQL (\(enhancement.provider))",
                        status: execution.status
                    )
                }
            }
            _ = await llm.finishDownstreamValidation(
                token: semanticToken,
                outcome: .finalRejection
            )
        }
        // Fall back to deterministic
        return hunt(query)
    }

    /// Translate a natural language query to SQL.
    private func translateQuery(_ query: String) -> (sql: String, interpretation: String)? {

        // === Time-based queries ===

        if query.contains("last hour") || query.contains("past hour") {
            let timeFilter = "timestamp > strftime('%s', 'now', '-1 hour')"
            if query.contains("alert") {
                return ("SELECT * FROM alerts WHERE \(timeFilter) ORDER BY timestamp DESC LIMIT 100",
                        "Alerts from the last hour")
            }
            return ("SELECT * FROM events WHERE \(timeFilter) ORDER BY timestamp DESC LIMIT 100",
                    "Events from the last hour")
        }

        if query.contains("last 24 hours") || query.contains("today") || query.contains("past day") {
            let timeFilter = "timestamp > strftime('%s', 'now', '-1 day')"
            if query.contains("alert") {
                return ("SELECT * FROM alerts WHERE \(timeFilter) ORDER BY timestamp DESC LIMIT 200",
                        "Alerts from the last 24 hours")
            }
            return ("SELECT * FROM events WHERE \(timeFilter) ORDER BY timestamp DESC LIMIT 200",
                    "Events from the last 24 hours")
        }

        // === Severity queries ===

        if query.contains("critical") {
            return ("SELECT * FROM alerts WHERE severity = 'critical' ORDER BY timestamp DESC LIMIT 100",
                    "All critical severity alerts")
        }

        // === Process queries ===

        if query.contains("unsigned") && (query.contains("process") || query.contains("binar")) {
            return ("SELECT * FROM events WHERE process_signer IS NULL OR process_signer = 'unsigned' ORDER BY timestamp DESC LIMIT 100",
                    "Unsigned process executions")
        }

        if query.contains("unsigned") && query.contains("network") {
            return ("SELECT * FROM events WHERE (process_signer IS NULL OR process_signer = 'unsigned') AND network_dest_ip IS NOT NULL ORDER BY timestamp DESC LIMIT 100",
                    "Network connections from unsigned processes")
        }

        // === File queries ===

        if query.contains("launch") && (query.contains("agent") || query.contains("daemon")) {
            return ("SELECT * FROM events WHERE file_path LIKE '%/LaunchAgents/%' OR file_path LIKE '%/LaunchDaemons/%' ORDER BY timestamp DESC LIMIT 100",
                    "LaunchAgent/LaunchDaemon file events")
        }

        if query.contains("ssh") && query.contains("key") {
            return ("SELECT * FROM events WHERE file_path LIKE '%/.ssh/%' ORDER BY timestamp DESC LIMIT 100",
                    "SSH key directory access events")
        }

        if query.contains("download") {
            return ("SELECT * FROM events WHERE file_path LIKE '%/Downloads/%' OR process_path LIKE '%/Downloads/%' ORDER BY timestamp DESC LIMIT 100",
                    "Events involving Downloads directory")
        }

        // === Network queries ===

        if query.contains("network") && (query.contains("unusual") || query.contains("suspicious") || query.contains("strange")) {
            return ("SELECT * FROM events WHERE network_dest_port IS NOT NULL AND network_dest_port NOT IN (80, 443, 8080, 8443, 22, 53) ORDER BY timestamp DESC LIMIT 100",
                    "Network connections to unusual ports (not 80, 443, 8080, 22, 53)")
        }

        if query.contains("external") && query.contains("connect") {
            return ("SELECT * FROM events WHERE network_dest_ip IS NOT NULL AND network_dest_ip NOT LIKE '10.%' AND network_dest_ip NOT LIKE '192.168.%' AND network_dest_ip NOT LIKE '127.%' ORDER BY timestamp DESC LIMIT 100",
                    "External (non-private) network connections")
        }

        // === AI tool queries ===

        if query.contains("claude") || query.contains("ai tool") || query.contains("cursor") || query.contains("copilot") {
            let aiFilter = "process_path LIKE '%claude%' OR process_path LIKE '%cursor%' OR process_path LIKE '%copilot%' OR process_path LIKE '%codex%'"
            if query.contains("alert") {
                return ("SELECT * FROM alerts WHERE process_path LIKE '%claude%' OR process_path LIKE '%cursor%' ORDER BY timestamp DESC LIMIT 100",
                        "Alerts involving AI coding tools")
            }
            return ("SELECT * FROM events WHERE \(aiFilter) ORDER BY timestamp DESC LIMIT 100",
                    "Events from AI coding tools")
        }

        // === MITRE queries ===

        if query.contains("credential") && query.contains("access") {
            return ("SELECT * FROM alerts WHERE mitre_tactics LIKE '%credential_access%' ORDER BY timestamp DESC LIMIT 100",
                    "Alerts with credential_access MITRE tactic")
        }

        if query.contains("persistence") {
            return ("SELECT * FROM alerts WHERE mitre_tactics LIKE '%persistence%' ORDER BY timestamp DESC LIMIT 100",
                    "Alerts with persistence MITRE tactic")
        }

        if query.contains("c2") || query.contains("command and control") || query.contains("command_and_control") {
            return ("SELECT * FROM alerts WHERE mitre_tactics LIKE '%command_and_control%' ORDER BY timestamp DESC LIMIT 100",
                    "Alerts with command_and_control MITRE tactic")
        }

        // === Process name search ===

        // Generic: "show me <process name>" / "find <process name>"
        let words = query.split(separator: " ").map(String.init)
        if let actionIdx = words.firstIndex(where: { ["show", "find", "search", "get", "list"].contains($0) }),
           actionIdx + 1 < words.count {
            let searchTerm = words[(actionIdx+1)...].joined(separator: " ")
                .replacingOccurrences(of: "me ", with: "")
                .replacingOccurrences(of: "all ", with: "")
                .trimmingCharacters(in: .whitespaces)

            if !searchTerm.isEmpty && searchTerm.count > 1 {
                // Search across multiple columns
                let escaped = searchTerm.replacingOccurrences(of: "'", with: "''")
                return ("SELECT * FROM events WHERE process_name LIKE '%\(escaped)%' OR process_path LIKE '%\(escaped)%' OR process_commandline LIKE '%\(escaped)%' OR file_path LIKE '%\(escaped)%' OR network_dest_ip LIKE '%\(escaped)%' ORDER BY timestamp DESC LIMIT 100",
                        "Searching for '\(searchTerm)' across process names, paths, command lines, file paths, and network IPs")
            }
        }

        // === Generic alert listing ===

        if query.contains("alert") || query.contains("detection") || query.contains("threat") {
            return ("SELECT * FROM alerts ORDER BY timestamp DESC LIMIT 50",
                    "Recent alerts")
        }

        if query.contains("event") {
            return ("SELECT * FROM events ORDER BY timestamp DESC LIMIT 50",
                    "Recent events")
        }

        return nil
    }

    /// Validate, route, and execute one query against exactly one read-only
    /// store. Kept internal so focused tests exercise the production policy,
    /// SQLite authorizer, timeout, and result bounds together.
    func executeSQL(_ sql: String) -> ThreatHuntSQLExecution {
        let store: ThreatHuntQueryStore
        switch ThreatHuntSQLPolicy.validate(sql) {
        case .accepted(let acceptedStore):
            store = acceptedStore
        case .rejected:
            return ThreatHuntSQLExecution(rows: [], status: .rejected)
        }

        let databasePath = store == .events
            ? eventsDatabasePath
            : alertsDatabasePath
        var db: OpaquePointer?
        guard SQLiteOpenPathPolicy.open(
            databasePath,
            database: &db,
            flags: SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX
        ) == SQLITE_OK,
              let handle = db else {
            return ThreatHuntSQLExecution(rows: [], status: .databaseUnavailable)
        }
        defer { sqlite3_close(handle) }
        sqlite3_busy_timeout(handle, Int32(min(limits.deadlineMilliseconds, 100)))

        // The authorizer constrains *what* the statement can do, while these
        // connection-local limits constrain how much parser/VM state a short
        // generated SELECT can build before the progress deadline starts
        // running. SQLCipher is compiled with in-memory temporary storage, so
        // bounding expression, compound-query, value and worker limits is also
        // part of the hunt memory boundary rather than merely parser hygiene.
        sqlite3_limit(
            handle,
            SQLITE_LIMIT_SQL_LENGTH,
            Int32(ThreatHuntSQLPolicy.maximumSQLBytes)
        )
        sqlite3_limit(handle, SQLITE_LIMIT_LENGTH, 256 * 1_024)
        sqlite3_limit(handle, SQLITE_LIMIT_COLUMN, Int32(limits.maxColumns))
        sqlite3_limit(handle, SQLITE_LIMIT_EXPR_DEPTH, 32)
        sqlite3_limit(handle, SQLITE_LIMIT_COMPOUND_SELECT, 4)
        sqlite3_limit(handle, SQLITE_LIMIT_VDBE_OP, 20_000)
        sqlite3_limit(handle, SQLITE_LIMIT_FUNCTION_ARG, 16)
        sqlite3_limit(handle, SQLITE_LIMIT_ATTACHED, 0)
        sqlite3_limit(handle, SQLITE_LIMIT_LIKE_PATTERN_LENGTH, 1_024)
        sqlite3_limit(handle, SQLITE_LIMIT_VARIABLE_NUMBER, 0)
        sqlite3_limit(handle, SQLITE_LIMIT_TRIGGER_DEPTH, 0)
        sqlite3_limit(handle, SQLITE_LIMIT_WORKER_THREADS, 0)
        sqlite3_limit(handle, SQLITE_LIMIT_PARSER_DEPTH, 64)
        sqlite3_enable_load_extension(handle, 0)

        let authorization = ThreatHuntAuthorizationContext(store: store)
        let authorizationPointer = Unmanaged.passRetained(authorization).toOpaque()
        defer {
            Unmanaged<ThreatHuntAuthorizationContext>
                .fromOpaque(authorizationPointer).release()
        }
        guard sqlite3_set_authorizer(
            handle,
            threatHuntAuthorizerCallback,
            authorizationPointer
        ) == SQLITE_OK else {
            return ThreatHuntSQLExecution(rows: [], status: .rejected)
        }

        let deadline = ThreatHuntDeadlineContext(
            milliseconds: limits.deadlineMilliseconds
        )
        let deadlinePointer = Unmanaged.passRetained(deadline).toOpaque()
        defer {
            Unmanaged<ThreatHuntDeadlineContext>
                .fromOpaque(deadlinePointer).release()
        }
        sqlite3_progress_handler(
            handle,
            limits.progressSteps,
            threatHuntProgressCallback,
            deadlinePointer
        )
        defer {
            sqlite3_progress_handler(handle, 0, nil, nil)
            sqlite3_set_authorizer(handle, nil, nil)
        }

        var stmt: OpaquePointer?
        let prepareResult = sqlite3_prepare_v2(handle, sql, -1, &stmt, nil)
        guard prepareResult == SQLITE_OK, let statement = stmt else {
            return ThreatHuntSQLExecution(
                rows: [],
                status: deadline.interrupted || prepareResult == SQLITE_INTERRUPT
                    ? .timedOut : .rejected
            )
        }
        defer { sqlite3_finalize(statement) }

        var results: [[String: String]] = []
        let columnCount = Int(sqlite3_column_count(statement))
        guard columnCount <= limits.maxColumns else {
            return ThreatHuntSQLExecution(rows: [], status: .resultLimitReached)
        }
        var returnedBytes = 0

        queryLoop: while true {
            let stepResult = sqlite3_step(statement)
            guard stepResult == SQLITE_ROW else {
                if stepResult == SQLITE_DONE {
                    return ThreatHuntSQLExecution(rows: results, status: .completed)
                }
                return ThreatHuntSQLExecution(
                    rows: results,
                    status: deadline.interrupted || stepResult == SQLITE_INTERRUPT
                        ? .timedOut : .rejected
                )
            }
            guard results.count < limits.maxRows else {
                return ThreatHuntSQLExecution(rows: results, status: .rowLimitReached)
            }

            var row: [String: String] = [:]
            for column in 0..<columnCount {
                let sqliteColumn = Int32(column)
                let rawName = sqlite3_column_name(statement, sqliteColumn)
                    .map { String(cString: $0) } ?? "column_\(column)"
                let name = String(rawName.prefix(256))
                let value: String
                switch sqlite3_column_type(statement, sqliteColumn) {
                case SQLITE_INTEGER:
                    value = String(sqlite3_column_int64(statement, sqliteColumn))
                case SQLITE_FLOAT:
                    value = String(sqlite3_column_double(statement, sqliteColumn))
                case SQLITE_TEXT:
                    let byteCount = min(
                        Int(sqlite3_column_bytes(statement, sqliteColumn)),
                        limits.maxCellBytes
                    )
                    if byteCount > 0,
                       let text = sqlite3_column_text(statement, sqliteColumn) {
                        value = String(
                            decoding: UnsafeBufferPointer(
                                start: text,
                                count: byteCount
                            ),
                            as: UTF8.self
                        )
                    } else {
                        value = ""
                    }
                case SQLITE_BLOB:
                    value = "<blob \(sqlite3_column_bytes(statement, sqliteColumn)) bytes>"
                default:
                    value = ""
                }

                let addedBytes = name.utf8.count + value.utf8.count
                guard returnedBytes + addedBytes <= limits.maxResultBytes else {
                    return ThreatHuntSQLExecution(
                        rows: results,
                        status: .resultLimitReached
                    )
                }
                returnedBytes += addedBytes
                row[name] = value
            }
            results.append(row)

            // A deadline can expire between SQLite VM progress callbacks while
            // Swift is converting a wide row. Check it at every row boundary as
            // well so result materialization shares the same wall-clock ceiling.
            if DispatchTime.now().uptimeNanoseconds >= deadline.deadline {
                deadline.interrupted = true
                break queryLoop
            }
        }
        return ThreatHuntSQLExecution(rows: results, status: .timedOut)
    }

    /// Get suggested queries for users who don't know what to search.
    public func suggestions() -> [String] {
        [
            "show critical alerts from last hour",
            "find unsigned processes with network connections",
            "show alerts involving AI tools",
            "find events in Downloads directory",
            "show credential access alerts",
            "find network connections to unusual ports",
            "show LaunchAgent persistence events",
            "find SSH key access",
            "show C2 command and control alerts",
            "show alerts from today",
        ]
    }
}
