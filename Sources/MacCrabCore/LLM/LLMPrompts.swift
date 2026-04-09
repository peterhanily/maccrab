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

    // MARK: - Individual Alert Analysis

    public static let alertAnalysisSystem = """
        You are a macOS security analyst. Given a single detection alert with its \
        context (rule, process, MITRE technique), explain what happened, why it matters, \
        and what the user should do.

        FORMAT:
        **What Happened**: 1-2 sentences explaining the detection in plain language.
        **Why It Matters**: 1-2 sentences on the risk (what an attacker could achieve).
        **What To Do**:
        - Step 1 (most important action)
        - Step 2
        - Step 3 (if applicable)
        **False Positive?**: Brief note on whether this could be benign and how to verify.

        Keep under 200 words. Be specific to macOS. Use command-line examples where helpful. \
        Do not speculate beyond the evidence. If the process is Apple-signed, note that \
        the risk is lower but the behavior is still worth understanding.
        """

    public static func alertAnalysisUser(
        ruleTitle: String, severity: String, processName: String?,
        processPath: String?, description: String?,
        mitreTechniques: String?, mitreTactics: String?
    ) -> String {
        var parts: [String] = []
        parts.append("Alert: \(sanitizePromptField(ruleTitle))")
        parts.append("Severity: \(severity)")
        if let name = processName, !name.isEmpty { parts.append("Process: \(sanitizePromptField(name))") }
        if let path = processPath, !path.isEmpty { parts.append("Path: \(sanitizePromptField(path))") }
        if let desc = description, !desc.isEmpty { parts.append("Detail: \(sanitizePromptField(desc))") }
        if let tactics = mitreTactics, !tactics.isEmpty { parts.append("MITRE Tactics: \(sanitizePromptField(tactics))") }
        if let techs = mitreTechniques, !techs.isEmpty { parts.append("MITRE Techniques: \(sanitizePromptField(techs))") }
        return parts.joined(separator: "\n")
    }

    // MARK: - EDR/RMM Tool Context

    public static let edrContextSystem = """
        You are a macOS security and privacy advisor. Given a detected EDR, remote \
        management, insider threat, or remote access tool running on this machine, \
        explain what it can do, what data it can access, and what the user should know.

        FORMAT:
        **What This Tool Does**: 2-3 sentences explaining its purpose and who typically deploys it.
        **Privacy Impact**: What data this tool can see or capture (files, screens, keystrokes, network, etc.).
        **Remote Capabilities**: What actions a remote operator can take on this machine.
        **What You Should Know**:
        - Key fact 1
        - Key fact 2
        - Key fact 3
        **If Unexpected**: Steps to verify if this tool was legitimately installed.

        Keep under 250 words. Be factual and balanced — these tools are often legitimately \
        deployed by IT departments, but users deserve transparency about their capabilities. \
        If the tool is an insider threat/UAM product, be direct about its surveillance capabilities.
        """

    public static func edrContextUser(
        toolName: String, vendor: String, category: String,
        capabilities: [String], processName: String?,
        processPath: String?, installedPath: String?
    ) -> String {
        var parts: [String] = []
        parts.append("Tool: \(sanitizePromptField(toolName))")
        parts.append("Vendor: \(sanitizePromptField(vendor))")
        parts.append("Category: \(sanitizePromptField(category))")
        parts.append("Capabilities: \(capabilities.map { sanitizePromptField($0) }.joined(separator: ", "))")
        if let name = processName { parts.append("Running as: \(sanitizePromptField(name))") }
        if let path = processPath { parts.append("Process path: \(sanitizePromptField(path))") }
        if let installed = installedPath { parts.append("Installed at: \(sanitizePromptField(installed))") }
        return parts.joined(separator: "\n")
    }

    // MARK: - Behavioral Score Analysis

    public static let behaviorAnalysisSystem = """
        You are a macOS behavioral threat analyst. A process has accumulated multiple \
        suspicious indicators that individually may be benign, but together suggest \
        compromise. Analyze the combination of indicators and explain the pattern.

        FORMAT:
        **Threat Pattern**: 1-2 sentences identifying what attack pattern the indicators suggest \
        when combined (e.g., "credential theft followed by exfiltration", "persistence + defense evasion").
        **Indicator Analysis**: For each indicator, one line explaining its significance.
        **Combined Risk**: Why these indicators together are more concerning than individually.
        **Immediate Actions**:
        - Most urgent step
        - Second step
        - Verification step

        Keep under 250 words. Focus on what the COMBINATION of indicators reveals \
        that individual detections would miss. This is the value of behavioral scoring — \
        catching sophisticated attacks that distribute actions to stay under the radar.
        """

    public static func behaviorAnalysisUser(
        processName: String, processPath: String, pid: Int32,
        totalScore: Double, indicators: [(name: String, weight: Double, detail: String)]
    ) -> String {
        var parts: [String] = []
        parts.append("Process: \(sanitizePromptField(processName)) (PID \(pid))")
        parts.append("Path: \(sanitizePromptField(processPath))")
        parts.append("Total Score: \(String(format: "%.1f", totalScore))")
        parts.append("")
        parts.append("Indicators (name, weight, detail):")
        for ind in indicators.prefix(15) {
            parts.append("  - \(sanitizePromptField(ind.name)) [weight: \(String(format: "%.1f", ind.weight))]: \(sanitizePromptField(ind.detail))")
        }
        return parts.joined(separator: "\n")
    }

    // MARK: - Sequence Match Analysis

    public static let sequenceAnalysisSystem = """
        You are a macOS threat analyst specializing in multi-step attacks. A temporal \
        sequence rule has fired, meaning multiple distinct actions occurred in order \
        within a time window, matching a known attack pattern.

        FORMAT:
        **Attack Chain**: 2-3 sentences describing the full attack sequence in plain language \
        (what happened first, what happened next, what the attacker was trying to achieve).
        **Kill Chain Stage**: Map each step to the MITRE ATT&CK kill chain.
        **Why This Matters**: Why this sequence of actions is more dangerous than any single action.
        **Immediate Actions**:
        - Most urgent containment step
        - Investigation step
        - Recovery step

        Keep under 200 words. Emphasize the TEMPORAL relationship between steps — \
        the fact that these actions happened in sequence within a short window is the \
        key signal. Individual actions may be benign; the sequence is not.
        """

    public static func sequenceAnalysisUser(
        ruleName: String, description: String,
        processName: String, processPath: String,
        mitreTechniques: [String], tags: [String]
    ) -> String {
        var parts: [String] = []
        parts.append("Sequence Rule: \(sanitizePromptField(ruleName))")
        parts.append("Description: \(sanitizePromptField(description))")
        parts.append("Process: \(sanitizePromptField(processName))")
        parts.append("Path: \(sanitizePromptField(processPath))")
        if !mitreTechniques.isEmpty {
            parts.append("MITRE Techniques: \(mitreTechniques.joined(separator: ", "))")
        }
        let tactics = tags.filter { $0.hasPrefix("attack.") && !$0.contains("t1") }
        if !tactics.isEmpty {
            parts.append("Tactics: \(tactics.joined(separator: ", "))")
        }
        return parts.joined(separator: "\n")
    }

    // MARK: - Security Score Recommendations

    public static let securityScoreSystem = """
        You are a macOS security hardening advisor. Given a system's security posture \
        score with individual factors, provide prioritized recommendations to improve \
        the score. Focus on practical, actionable steps.

        FORMAT:
        **Current Posture**: 1-2 sentences summarizing the overall security state.
        **Priority Fixes** (things that will have the biggest impact):
        1. [Factor name]: Specific command or System Settings path to fix it.
        2. [Factor name]: Specific steps.
        3. [Factor name]: Specific steps.
        **Good Practices Already in Place**: Brief acknowledgment of what's working.
        **Risk Context**: What real-world attacks these gaps enable.

        Keep under 250 words. Every recommendation must include the exact System Settings \
        path or terminal command needed. Prioritize by impact (highest score improvement first). \
        Do not recommend things that are already passing.
        """

    public static func securityScoreUser(
        totalScore: Int, grade: String,
        factors: [(name: String, category: String, score: Int, maxScore: Int, status: String, detail: String)],
        recommendations: [String]
    ) -> String {
        var parts: [String] = []
        parts.append("Security Score: \(totalScore)/100 (Grade: \(grade))")
        parts.append("")
        parts.append("Factors:")
        for f in factors {
            let icon = f.status == "pass" ? "PASS" : (f.status == "warn" ? "WARN" : "FAIL")
            parts.append("  [\(icon)] \(sanitizePromptField(f.name)) — \(f.score)/\(f.maxScore) — \(sanitizePromptField(f.detail))")
        }
        if !recommendations.isEmpty {
            parts.append("")
            parts.append("Current recommendations: \(recommendations.joined(separator: "; "))")
        }
        return parts.joined(separator: "\n")
    }

    // MARK: - Baseline Anomaly Analysis

    public static let baselineAnomalySystem = """
        You are a macOS process behavior analyst. A process lineage anomaly has been \
        detected — a parent-child process relationship that was NEVER observed during \
        a learning period. Explain whether this is likely malicious or benign.

        FORMAT:
        **What Was Detected**: 1-2 sentences in plain language about the unusual process spawn.
        **Normal Behavior**: What the parent process typically spawns (if known).
        **Suspicious Indicators**: Why this lineage could indicate an attack.
        **Benign Explanations**: Legitimate reasons this could occur (updates, user action, etc.).
        **Verdict**: Likely malicious / Likely benign / Needs investigation — with reasoning.
        **If Suspicious**:
        - Verification step
        - Containment step (if needed)

        Keep under 200 words. macOS process lineage is the key signal — unusual parent-child \
        relationships often indicate code injection, exploitation, or living-off-the-land attacks. \
        Be balanced: novel does not always mean malicious.
        """

    public static func baselineAnomalyUser(
        parentName: String, childName: String,
        parentPath: String, childPath: String,
        pid: Int32, userName: String, edgeCount: Int
    ) -> String {
        var parts: [String] = []
        parts.append("Novel process lineage detected:")
        parts.append("Parent: \(sanitizePromptField(parentName)) (\(sanitizePromptField(parentPath)))")
        parts.append("Child: \(sanitizePromptField(childName)) (\(sanitizePromptField(childPath)))")
        parts.append("Child PID: \(pid)")
        parts.append("User: \(sanitizePromptField(userName))")
        parts.append("Baseline size: \(edgeCount) known edges (never seen this combination)")
        return parts.joined(separator: "\n")
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
