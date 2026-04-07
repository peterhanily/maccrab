// ThreatHunter.swift
// MacCrabCore
//
// Translates natural language threat hunting queries into database searches.
// Enables security analysts to query events and alerts using plain English.
// Uses pattern matching (not LLM) for v1 — maps common phrases to SQL queries.

import Foundation
import SQLite3
import os.log

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
    }

    private let databasePath: String
    private let llmService: LLMService?

    public init(databasePath: String, llmService: LLMService? = nil) {
        self.databasePath = databasePath
        self.llmService = llmService
    }

    /// Execute a natural language threat hunting query.
    public func hunt(_ query: String) -> HuntResult? {
        let start = Date()

        // Normalize the query
        let normalized = query.lowercased().trimmingCharacters(in: .whitespacesAndNewlines)

        // Try to match against known query patterns
        guard let (sql, interpretation) = translateQuery(normalized) else {
            return HuntResult(
                query: query, sqlQuery: "", resultCount: 0, results: [],
                executionTime: 0, interpretation: "Could not interpret query. Try: 'show alerts from last hour', 'find unsigned processes', 'network connections to unusual ports'"
            )
        }

        // Execute the SQL
        let results = executeSQL(sql)
        let elapsed = Date().timeIntervalSince(start)

        return HuntResult(
            query: query, sqlQuery: sql, resultCount: results.count,
            results: results, executionTime: elapsed, interpretation: interpretation
        )
    }

    /// Execute a threat hunting query with LLM enhancement.
    /// Falls back to deterministic pattern matching if LLM is unavailable.
    public func huntEnhanced(_ query: String) async -> HuntResult? {
        // Try LLM first
        if let llm = llmService {
            let start = Date()
            if let enhancement = await llm.query(
                systemPrompt: LLMPrompts.threatHuntSystem,
                userPrompt: LLMPrompts.threatHuntUser(query: query),
                maxTokens: 512, temperature: 0.1, useCache: false
            ) {
                let sql = enhancement.response.trimmingCharacters(in: .whitespacesAndNewlines)
                // Validate: must be SELECT, no mutations, no semicolons
                if isValidSQL(sql) {
                    let results = executeSQL(sql)
                    let elapsed = Date().timeIntervalSince(start)
                    return HuntResult(
                        query: query, sqlQuery: sql, resultCount: results.count,
                        results: results, executionTime: elapsed,
                        interpretation: "LLM-generated SQL (\(enhancement.provider))"
                    )
                }
            }
        }
        // Fall back to deterministic
        return hunt(query)
    }

    /// Validate LLM-generated SQL is safe to execute.
    /// Whitelist approach: only allow simple SELECT queries.
    private func isValidSQL(_ sql: String) -> Bool {
        // Max length guard
        guard sql.count < 2000 else { return false }

        let trimmed = sql.trimmingCharacters(in: .whitespacesAndNewlines)

        // Strip SQL comments before validation
        let noComments = trimmed
            .replacingOccurrences(of: #"--[^\n]*"#, with: " ", options: .regularExpression)
            .replacingOccurrences(of: #"/\*[\s\S]*?\*/"#, with: " ", options: .regularExpression)
            .trimmingCharacters(in: .whitespacesAndNewlines)

        let upper = noComments.uppercased()

        // Must start with SELECT
        guard upper.hasPrefix("SELECT") else { return false }

        // No semicolons (prevent multi-statement injection)
        if noComments.contains(";") { return false }

        // Comprehensive forbidden keyword list
        let forbidden = [
            "DELETE", "UPDATE", "INSERT", "DROP", "ALTER", "CREATE",
            "ATTACH", "DETACH", "PRAGMA", "VACUUM", "ANALYZE",
            "REINDEX", "REPLACE", "SAVEPOINT", "RELEASE", "ROLLBACK",
            "BEGIN", "COMMIT", "GRANT", "REVOKE",
        ]

        // Check for forbidden keywords as whole words (not substrings)
        for keyword in forbidden {
            let pattern = "\\b\(keyword)\\b"
            if upper.range(of: pattern, options: .regularExpression) != nil {
                return false
            }
        }

        return true
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
                return ("SELECT * FROM events WHERE process_name LIKE '%\(escaped)%' OR process_path LIKE '%\(escaped)%' OR process_commandline LIKE '%\(escaped)%' OR file_path LIKE '%\(escaped)%' ORDER BY timestamp DESC LIMIT 100",
                        "Searching for '\(searchTerm)' across process names, paths, command lines, and file paths")
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

    /// Execute a SQL query against the events database.
    private func executeSQL(_ sql: String) -> [[String: String]] {
        // Use SQLite3 C API directly (same pattern as EventStore)
        var db: OpaquePointer?
        guard sqlite3_open_v2(databasePath, &db, SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX, nil) == SQLITE_OK,
              let handle = db else {
            return []
        }
        defer { sqlite3_close(handle) }

        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(handle, sql, -1, &stmt, nil) == SQLITE_OK, let s = stmt else {
            return []
        }
        defer { sqlite3_finalize(s) }

        var results: [[String: String]] = []
        let colCount = sqlite3_column_count(s)

        while sqlite3_step(s) == SQLITE_ROW {
            var row: [String: String] = [:]
            for i in 0..<colCount {
                let name = String(cString: sqlite3_column_name(s, i))
                if let text = sqlite3_column_text(s, i) {
                    row[name] = String(cString: text)
                }
            }
            results.append(row)
        }

        return results
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
