// BuiltinRuleCatalog.swift
// MacCrabCore
//
// The hardcoded `maccrab.*` detections are emitted directly in code (EventLoop,
// MonitorTasks, DaemonTimers, …) rather than from YAML, so historically they did
// NOT appear in the dashboard's Rules view and could not be tuned. This catalog
// gives each one presentation metadata so the Rules view can list it (read-only
// content) alongside YAML rules, and `BuiltinRuleSettings` lets operators
// enable/disable + override severity — applied at the single AlertSink chokepoint
// (mute the alert; the detection + any protective action still run).
//
// Some emission ids are dynamic (e.g. `maccrab.git.<eventType>`,
// `maccrab.usb.<connected|disconnected>`). Those are catalogued under their
// family base id; AlertSink does a longest-prefix match so the base setting
// governs the whole family.

import Foundation

public struct BuiltinRuleDefinition: Sendable, Hashable {
    public let id: String
    public let title: String
    public let description: String
    public let defaultSeverity: Severity
    public let category: String
    public let tactics: String      // comma-separated attack.* tactics
    public let techniques: String   // comma-separated attack.t* techniques

    public init(_ id: String, _ title: String, _ description: String,
                _ defaultSeverity: Severity, _ category: String,
                _ tactics: String = "", _ techniques: String = "") {
        self.id = id; self.title = title; self.description = description
        self.defaultSeverity = defaultSeverity; self.category = category
        self.tactics = tactics; self.techniques = techniques
    }
}

public enum BuiltinRuleCatalog {
    public static let all: [BuiltinRuleDefinition] = [
        // — AI Guard —
        .init("maccrab.ai-guard.credential-access", "AI Tool Accessed Credentials",
              "An AI coding tool (Claude Code, Cursor, …) read credential files / keychains.",
              .high, "AI Guard", "attack.credential_access", "attack.t1552.001"),
        .init("maccrab.ai-guard.boundary-violation", "AI Tool Wrote Outside Project",
              "An AI tool wrote outside its project directory boundary.",
              .high, "AI Guard", "attack.defense_evasion"),
        .init("maccrab.ai-guard.prompt-injection", "LLM Prompt Injection",
              "Prompt-injection patterns detected in content an AI tool processed.",
              .high, "AI Guard", "attack.initial_access"),
        .init("maccrab.ai-guard.file-injection", "AI Tool Malicious File Injection",
              "An AI tool wrote a file matching a malicious-injection signature.",
              .high, "AI Guard"),
        .init("maccrab.ai-guard.network-sandbox", "AI Tool Network Sandbox Violation",
              "An AI tool's subprocess made a network connection outside its sandbox.",
              .high, "AI Guard", "attack.command_and_control"),
        .init("maccrab.ai-guard.mcp", "MCP Security Event",
              "An MCP server configuration or runtime anomaly across AI tools.",
              .high, "AI Guard"),
        // — Supply chain / prevention —
        .init("maccrab.supply-chain.fresh-package", "Fresh Package Installed",
              "A very recently published package was installed (typosquat / supply-chain risk).",
              .medium, "Supply Chain", "attack.initial_access", "attack.t1195.002"),
        .init("maccrab.prevention.supply-chain-blocked", "Package Install Blocked",
              "The supply-chain gate killed a high-risk package installer.",
              .critical, "Prevention", "attack.initial_access", "attack.t1195.002"),
        .init("maccrab.prevention.sandbox-suspicious", "Sandboxed Process Suspicious",
              "A sandbox-wrapped process exhibited suspicious behavior.",
              .critical, "Prevention"),
        // — Delivery / integrity —
        .init("maccrab.clickfix.paste-and-run", "ClickFix Paste-and-Run",
              "A shell exec carried a delivery-shaped payload (curl|bash) recently copied to the clipboard.",
              .high, "Delivery", "attack.execution,attack.initial_access", "attack.t1059.004,attack.t1204"),
        .init("maccrab.notarization.cert-revoked", "Revoked-Cert Binary Executed",
              "A binary executed with a revoked Developer-ID certificate.",
              .high, "Integrity", "attack.defense_evasion"),
        .init("maccrab.correlator.cross-process", "Cross-Process Correlation",
              "Suspicious activity correlated across a process-lineage graph.",
              .high, "Correlation"),
        // — Threat intel —
        .init("maccrab.threat-intel.ip-match", "Threat-Intel IP Match",
              "A connection matched a threat-intel IP indicator.",
              .high, "Threat Intel", "attack.command_and_control"),
        .init("maccrab.threat-intel.domain-match", "Threat-Intel Domain Match",
              "A DNS query matched a threat-intel domain indicator.",
              .high, "Threat Intel", "attack.command_and_control"),
        .init("maccrab.threat-intel.hash-match", "Threat-Intel Hash Match",
              "An executed binary matched a threat-intel file-hash indicator.",
              .high, "Threat Intel"),
        // — Network —
        .init("maccrab.network.doh-evasion", "DoH Evasion",
              "DNS-over-HTTPS evasion behavior detected.",
              .medium, "Network", "attack.command_and_control", "attack.t1572"),
        .init("maccrab.dns.dga-detection", "DNS DGA",
              "Domain-generation-algorithm-style high-entropy DNS queries.",
              .medium, "Network", "attack.command_and_control"),
        .init("maccrab.dns.tunneling-detection", "DNS Tunneling",
              "DNS-tunneling exfiltration pattern detected.",
              .medium, "Network", "attack.exfiltration"),
        .init("maccrab.dns.threat-intel-match", "DNS Threat-Intel Match",
              "A DNS query matched a threat-intel indicator.",
              .high, "Network"),
        .init("maccrab.git", "Git Security Event",
              "Git credential-helper abuse, SSH-agent hijack, or a malicious git hook.",
              .medium, "Repository", "attack.credential_access"),
        // — Behavior / intent —
        .init("maccrab.behavior.composite", "Behavioral Anomaly",
              "Accumulated weighted behavioral indicators crossed the alert threshold.",
              .medium, "Behavior"),
        .init("maccrab.intent.bayesian-posterior", "Intent Classifier",
              "The Bayesian intent engine raised a tactic posterior above threshold.",
              .medium, "Intent"),
        // — Deep / monitors —
        .init("maccrab.deep.event-tap-keylogger", "Keylogger Event Tap",
              "A process installed a CGEventTap consistent with keylogging.",
              .high, "Deep Security", "attack.collection", "attack.t1056.001"),
        .init("maccrab.clipboard.sensitive-data", "Sensitive Clipboard Data",
              "Sensitive data (keys/tokens) detected on the clipboard.",
              .high, "Data Leakage", "attack.collection"),
        .init("maccrab.usb", "USB Device Event",
              "A USB mass-storage / HID device connected or disconnected.",
              .medium, "USB"),
        .init("maccrab.browser", "Browser Extension Event",
              "A browser extension was installed or modified.",
              .medium, "Browser"),
        .init("maccrab.ultrasonic", "Ultrasonic Attack",
              "An ultrasonic (DolphinAttack/NUIT) audio-injection indicator.",
              .high, "Ultrasonic"),
        .init("maccrab.forensic.hidden-process", "Hidden Process",
              "A process visible to one enumeration API but hidden from another (rootkit indicator).",
              .high, "Forensic", "attack.defense_evasion", "attack.t1014"),
        .init("maccrab.tempest", "TEMPEST / Van Eck",
              "An SDR device or display anomaly consistent with electromagnetic eavesdropping.",
              .high, "TEMPEST"),
        .init("maccrab.edr", "EDR / RMM Tool",
              "An EDR / RMM / insider-threat / remote-access tool was discovered.",
              .high, "EDR"),
        // — Scheduled —
        .init("maccrab.vuln", "Vulnerable Software",
              "An installed application matched a known CVE.",
              .medium, "Vulnerabilities"),
        .init("maccrab.privacy", "Privacy Anomaly",
              "An app-privacy auditor anomaly (unexpected TCC-protected access).",
              .medium, "Privacy"),
        // — LLM advisory (info) —
        .init("maccrab.llm", "LLM Analysis",
              "Advisory LLM analysis output (investigation summary, defense recommendation, scoring).",
              .informational, "LLM Analysis"),
    ]

    public static let byId: [String: BuiltinRuleDefinition] =
        Dictionary(all.map { ($0.id, $0) }, uniquingKeysWith: { a, _ in a })
}
