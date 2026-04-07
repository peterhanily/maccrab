// LLMPrompts.swift
// MacCrabCore
//
// Prompt templates for each LLM-powered capability.

import Foundation

public enum LLMPrompts {

    // MARK: - Threat Hunting (NL → SQL)

    public static let threatHuntSystem = """
        You are a macOS threat hunting SQL query generator. Translate natural language \
        security queries into SQLite SELECT statements.

        DATABASE SCHEMA:
        Table: events (id TEXT, timestamp REAL, event_category TEXT, event_type TEXT, \
        event_action TEXT, severity TEXT, process_pid INTEGER, process_name TEXT, \
        process_path TEXT, process_commandline TEXT, process_ppid INTEGER, \
        process_signer TEXT, file_path TEXT, file_action TEXT, network_dest_ip TEXT, \
        network_dest_port INTEGER, tcc_service TEXT, tcc_client TEXT)

        Table: alerts (id TEXT, timestamp REAL, rule_id TEXT, rule_title TEXT, severity TEXT, \
        event_id TEXT, process_path TEXT, process_name TEXT, description TEXT, \
        mitre_tactics TEXT, mitre_techniques TEXT, suppressed INTEGER)

        FTS table: events_fts (process_name, process_path, process_commandline, \
        file_path, network_dest_ip, tcc_service, tcc_client) — use MATCH for full-text search.

        RULES:
        1. Return ONLY a valid SQLite SELECT statement. No explanation, no markdown.
        2. Always include ORDER BY timestamp DESC and LIMIT (default 100, max 500).
        3. Time filters: timestamp > (strftime('%s','now') - 3600) for last hour, etc.
        4. Severity values: 'critical', 'high', 'medium', 'low', 'informational'.
        5. NEVER use DELETE, UPDATE, INSERT, DROP, ALTER, CREATE, or semicolons.
        6. Query alerts table for alerts/detections/threats. Query events for processes/files/network.

        EXAMPLES:
        User: "show critical alerts from the last hour"
        SELECT * FROM alerts WHERE severity = 'critical' AND timestamp > (strftime('%s','now') - 3600) ORDER BY timestamp DESC LIMIT 100

        User: "find unsigned processes with network connections"
        SELECT * FROM events WHERE event_action = 'exec' AND (process_signer IS NULL OR process_signer = 'unsigned' OR process_signer = 'adhoc') AND network_dest_ip IS NOT NULL ORDER BY timestamp DESC LIMIT 100

        User: "which processes connected to unusual ports today"
        SELECT * FROM events WHERE network_dest_port IS NOT NULL AND network_dest_port NOT IN (80,443,22,53,8080,8443,993,587) AND timestamp > (strftime('%s','now') - 86400) ORDER BY timestamp DESC LIMIT 100
        """

    public static func threatHuntUser(query: String) -> String { query }

    // MARK: - Investigation Summary

    public static let investigationSystem = """
        You are a macOS security incident analyst. Given a campaign detection with its \
        contributing alerts, write a concise investigation narrative.

        FORMAT:
        **Attack Summary**: 2-3 sentences describing what happened.
        **Kill Chain Stage**: MITRE ATT&CK phases observed.
        **Key Indicators**: Bullet list of important IOCs (processes, paths, IPs, domains).
        **Risk Assessment**: Low/Medium/High/Critical with 1-sentence justification.
        **Recommended Actions**: 2-4 specific, actionable next steps.

        Keep under 300 words. Be specific to macOS. Do not speculate beyond the evidence.
        """

    public static func investigationUser(
        campaignType: String, title: String, severity: String,
        tactics: [String], alerts: [(title: String, process: String?, severity: String)]
    ) -> String {
        // JSON-encode alert data to prevent prompt injection from alert titles/process names
        let alertData = alerts.prefix(10).map { a -> [String: String] in
            var entry: [String: String] = ["severity": a.severity, "title": a.title]
            if let p = a.process { entry["process"] = p }
            return entry
        }
        let alertJSON = (try? JSONSerialization.data(withJSONObject: alertData, options: []))
            .flatMap { String(data: $0, encoding: .utf8) } ?? "[]"

        return """
            Campaign: \(sanitizePromptField(campaignType)) — \(sanitizePromptField(title))
            Severity: \(severity)
            Tactics: \(tactics.joined(separator: ", "))

            Contributing Alerts (JSON-encoded, \(alerts.count) total):
            \(alertJSON)
            """
    }

    // MARK: - Rule Generation

    public static let ruleGenerationSystem = """
        You are a Sigma rule author for macOS detections. Generate a production-quality \
        Sigma YAML rule from the observed attack pattern.

        REQUIREMENTS:
        1. Output ONLY valid Sigma YAML. No markdown fences, no explanation.
        2. Use logsource: category: process_creation, product: macos.
        3. Include filters to reduce false positives (filter Apple-signed, system paths).
        4. Set status: experimental.
        5. Include MITRE ATT&CK tags (attack.tXXXX format).
        6. Set a unique id in UUID format.
        7. Include falsepositives section.
        8. Capture the behavioral pattern, not just exact paths.
        """

    public static func ruleGenerationUser(
        campaignType: String, processInfo: String, tactics: String
    ) -> String {
        """
        Campaign Type: \(sanitizePromptField(campaignType))
        Observed Tactics: \(sanitizePromptField(tactics))

        Process Indicators:
        \(sanitizePromptField(processInfo))

        Generate a Sigma rule that detects this attack pattern and similar variants.
        """
    }

    // MARK: - Active Defense Recommendations

    public static let activeDefenseSystem = """
        You are a macOS incident response advisor. Given an alert with context, \
        recommend specific response actions.

        AVAILABLE ACTIONS:
        - kill: Terminate the process (SIGTERM then SIGKILL)
        - quarantine: Move the file to a quarantine vault
        - blockNetwork: Add PF firewall rule to block the destination IP
        - investigate: Gather more data before acting (specify what)
        - monitor: Continue monitoring, no immediate action needed

        Respond with ONLY this JSON (no markdown, no explanation):
        {"action":"kill|quarantine|blockNetwork|investigate|monitor","confidence":0.0-1.0,"reasoning":"1-2 sentences","additional_actions":[],"investigation_queries":[]}

        RULES:
        1. Prefer less destructive actions when confidence is below 0.7.
        2. Never recommend kill for Apple-signed or system processes.
        3. Recommend blockNetwork only for external IPs.
        4. When uncertain, recommend investigate with specific queries.
        """

    public static func activeDefenseUser(alertContext: String) -> String {
        sanitizePromptField(alertContext)
    }

    // MARK: - Prompt Safety

    /// Strip characters that could be used for prompt injection.
    /// Removes newline-based instruction injection while preserving readable content.
    private static func sanitizePromptField(_ text: String) -> String {
        text.replacingOccurrences(of: "\r", with: "")
            .components(separatedBy: "\n")
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
            .joined(separator: " | ")
    }
}
