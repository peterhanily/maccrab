// ModuleStatus.swift
// MacCrabCore
//
// v1.8.1: surface stable / experimental labels per subsystem so the
// dashboard, CLI, and docs can communicate maturity. Mirrors the
// `status:` field on detection rules but at the module level.
//
// External reviewer feedback called out that MacCrab's feature surface
// is large for an alpha tool and that experimental and stable code
// should be visually distinguished. This file is the canonical answer.

import Foundation

/// Maturity classification for a MacCrab subsystem.
public enum ModuleMaturity: String, Codable, Sendable, CaseIterable {
    /// Production-ready by current alpha standards: stable APIs,
    /// substantial test coverage, in active use on the maintainer's
    /// host, no known correctness issues.
    case stable

    /// Functional but actively iterating. May produce false positives,
    /// have rough UX, or change shape between releases. Safe to enable
    /// — won't break the daemon — but treat its output as advisory.
    case experimental

    /// Built-in but disabled by default. Requires explicit opt-in
    /// via daemon_config or environment variable. Documented edges,
    /// not for casual use.
    case optIn
}

/// Catalog of MacCrab subsystems with maturity classification.
/// Surfaced in the dashboard's About panel and exported to docs.
public struct ModuleStatus: Sendable {
    public let id: String
    public let name: String
    public let category: String          // "detection" | "collector" | "output" | "ai" | "prevention" | "ui"
    public let maturity: ModuleMaturity
    public let summary: String

    public init(id: String, name: String, category: String, maturity: ModuleMaturity, summary: String) {
        self.id = id
        self.name = name
        self.category = category
        self.maturity = maturity
        self.summary = summary
    }

    /// Canonical catalog. Update when adding / changing subsystems.
    /// Order is render order in the About panel.
    public static let catalog: [ModuleStatus] = [
        // ─── Core detection (stable) ─────────────────────────────────
        .init(id: "rule-engine", name: "Rule engine",
              category: "detection", maturity: .stable,
              summary: "Sigma-compatible YAML → JSON predicates. 483 rules (436 single-event + 41 sequence + 6 graph) indexed by category."),
        .init(id: "es-collector", name: "Endpoint Security collector",
              category: "collector", maturity: .stable,
              summary: "Native ES client for exec/fork/exit/file/network/signal events."),
        .init(id: "alert-store", name: "Alert + campaign storage",
              category: "detection", maturity: .stable,
              summary: "Per-tier SQLite stores with retention + size-cap discipline."),
        .init(id: "deduplicator", name: "Alert deduplicator",
              category: "detection", maturity: .stable,
              summary: "Single-sink chokepoint for all alert insertion. Per-rule dismissal feedback."),

        // ─── Detection (experimental — actively iterating) ──────────
        .init(id: "sequence-engine", name: "Sequence engine",
              category: "detection", maturity: .experimental,
              summary: "41 multi-step sequence rules with bounded windows."),
        .init(id: "campaign-detector", name: "Campaign detector",
              category: "detection", maturity: .experimental,
              summary: "Kill chain, alert storm, AI compromise, lateral movement clustering."),
        .init(id: "behavior-scoring", name: "Behavioral scoring",
              category: "detection", maturity: .experimental,
              summary: "70+ weighted indicators with feedback-adjusted weights."),
        .init(id: "baseline-engine", name: "Baseline anomaly",
              category: "detection", maturity: .experimental,
              summary: "Welford z-score + 2nd-order Markov process tree anomaly."),
        .init(id: "topology-anomaly", name: "Topology anomaly",
              category: "detection", maturity: .experimental,
              summary: "Process-graph structural-novelty detection."),
        .init(id: "cross-process-correlator", name: "Cross-process correlator",
              category: "detection", maturity: .experimental,
              summary: "Multi-process activity-pattern correlation across lineage graph."),

        // ─── Collectors (mixed) ─────────────────────────────────────
        .init(id: "unified-log", name: "Unified log collector",
              category: "collector", maturity: .stable,
              summary: "18 macOS subsystems incl. Bluetooth, Wi-Fi, AirDrop."),
        .init(id: "network-collector", name: "Network collector",
              category: "collector", maturity: .stable,
              summary: "TCP/UDP connection tracking via lsof poll."),
        .init(id: "dns-collector", name: "DNS collector",
              category: "collector", maturity: .stable,
              summary: "BPF-based DNS query capture."),
        .init(id: "tcc-monitor", name: "TCC monitor",
              category: "collector", maturity: .stable,
              summary: "Privacy-permission grant/revoke detection."),
        .init(id: "fsevents", name: "FSEvents collector",
              category: "collector", maturity: .stable,
              summary: "Filesystem event fallback when ES is unavailable (non-root dev mode)."),
        .init(id: "edr-monitor", name: "EDR / RMM scanner",
              category: "collector", maturity: .stable,
              summary: "Discovery of 30+ EDR/MDM/insider-threat/remote-access tools."),
        .init(id: "browser-ext-monitor", name: "Browser extension monitor",
              category: "collector", maturity: .stable,
              summary: "Chrome/Firefox/Brave/Edge/Arc extension inventory."),
        .init(id: "rootkit-detector", name: "Rootkit detector",
              category: "collector", maturity: .stable,
              summary: "Dual-API process cross-reference (proc_listpids vs ps)."),
        .init(id: "event-tap-monitor", name: "Event tap / keylogger detector",
              category: "collector", maturity: .experimental,
              summary: "Detects processes with accessibility permission consuming key events."),
        .init(id: "system-policy-monitor", name: "System policy monitor",
              category: "collector", maturity: .stable,
              summary: "SIP / XProtect / MDM / auth-plugin posture."),
        .init(id: "usb-monitor", name: "USB monitor",
              category: "collector", maturity: .experimental,
              summary: "USB device connect/disconnect."),
        .init(id: "clipboard-monitor", name: "Clipboard monitor",
              category: "collector", maturity: .experimental,
              summary: "Clipboard content + injection-pattern detection."),
        .init(id: "mcp-monitor", name: "MCP server monitor",
              category: "collector", maturity: .experimental,
              summary: "MCP server config inventory across AI tools."),
        .init(id: "ultrasonic-monitor", name: "Ultrasonic / DolphinAttack",
              category: "collector", maturity: .optIn,
              summary: "Audio-injection detection. Requires microphone permission. Off by default."),
        .init(id: "tempest-monitor", name: "TEMPEST / Van Eck",
              category: "collector", maturity: .optIn,
              summary: "SDR device + display anomaly detection. Research-grade."),

        // ─── AI Guard (experimental cluster) ────────────────────────
        .init(id: "ai-tool-registry", name: "AI tool registry",
              category: "ai", maturity: .experimental,
              summary: "Catalog of known AI coding tools (Claude, Cursor, Copilot, etc.)."),
        .init(id: "ai-process-tracker", name: "AI process tracker",
              category: "ai", maturity: .experimental,
              summary: "Per-AI-tool session lineage from process ancestry."),
        .init(id: "agent-lineage", name: "Agent lineage service",
              category: "ai", maturity: .experimental,
              summary: "Weaves ES events into per-AI-session timelines."),
        .init(id: "credential-fence", name: "Credential fence",
              category: "ai", maturity: .experimental,
              summary: "Watches AI agents for credential file access (.aws, .ssh, etc.)."),
        .init(id: "project-boundary", name: "Project boundary",
              category: "ai", maturity: .experimental,
              summary: "Detects AI agent writes outside the active project."),
        .init(id: "prompt-injection", name: "Prompt injection scanner",
              category: "ai", maturity: .experimental,
              summary: "Pattern + LLM-based prompt-injection detection in agent inputs."),
        .init(id: "mcp-attributor", name: "MCP attributor",
              category: "ai", maturity: .experimental,
              summary: "Attributes events back to specific MCP servers via process ancestry."),

        // ─── Outputs (mostly stable) ────────────────────────────────
        .init(id: "notification-output", name: "OS notifications",
              category: "output", maturity: .stable,
              summary: "User-notification delivery for alerts."),
        .init(id: "webhook-output", name: "Webhook output",
              category: "output", maturity: .stable,
              summary: "POST alerts to a configured webhook URL with TLS + SSRF policy."),
        .init(id: "syslog-output", name: "Syslog output",
              category: "output", maturity: .stable,
              summary: "Local syslog forwarding."),
        .init(id: "splunk-hec", name: "Splunk HEC output",
              category: "output", maturity: .stable,
              summary: "HTTP Event Collector with token + TLS."),
        .init(id: "elastic-bulk", name: "Elastic Bulk output",
              category: "output", maturity: .stable,
              summary: "Elasticsearch _bulk endpoint."),
        .init(id: "datadog-logs", name: "Datadog Logs output",
              category: "output", maturity: .stable,
              summary: "Datadog HTTP intake."),
        .init(id: "wazuh-api", name: "Wazuh API output",
              category: "output", maturity: .experimental,
              summary: "Wazuh manager API forwarding."),
        .init(id: "s3-output", name: "S3 / S3-compatible output",
              category: "output", maturity: .stable,
              summary: "S3 / MinIO / R2 / Wasabi alert archive."),
        .init(id: "sftp-output", name: "SFTP output",
              category: "output", maturity: .experimental,
              summary: "SFTP alert log shipping."),
        .init(id: "otlp-output", name: "OpenTelemetry (OTLP) output",
              category: "output", maturity: .experimental,
              summary: "OTLP HTTP/JSON span export. v1.11.0: demoted from .stable — the OTLPOutput actor exists but DaemonSetup.buildOutput(spec:) does not yet accept `{\"type\": \"otlp\"}` entries (audit functionality HIGH). The receiver half (Agent Traces, separate row below) remains stable. Tracking re-promotion to .stable once the buildOutput arm lands."),
        .init(id: "agent-traces-receiver", name: "Agent Traces (OTLP receiver + lineage)",
              category: "ai", maturity: .stable,
              summary: "Loopback OTLP receiver + W3C TRACEPARENT correlation between AI-agent activity and kernel events. New in v1.9.0."),

        // ─── Prevention (default-off discipline) ────────────────────
        .init(id: "response-engine", name: "Response action engine",
              category: "prevention", maturity: .experimental,
              summary: "Per-rule kill / quarantine / network-block / runScript / TCC-revoke. All default-off."),
        .init(id: "dns-sinkhole", name: "DNS sinkhole",
              category: "prevention", maturity: .experimental,
              summary: "Block DNS resolution for known-bad domains via /etc/hosts overlay."),
        .init(id: "network-blocker", name: "Network blocker",
              category: "prevention", maturity: .experimental,
              summary: "Per-process or per-domain network blocking via PF / NEFilter."),
        .init(id: "persistence-guard", name: "Persistence guard",
              category: "prevention", maturity: .experimental,
              summary: "Blocks LaunchAgent / LaunchDaemon writes by suspicious processes."),

        // ─── Cross-cutting (LLM, fleet) ─────────────────────────────
        .init(id: "llm-orchestration", name: "LLM orchestration",
              category: "ai", maturity: .experimental,
              summary: "5 backend providers (Ollama, Claude, OpenAI, Mistral, Gemini). Advisory only."),
        .init(id: "fleet-client", name: "Fleet telemetry",
              category: "output", maturity: .optIn,
              summary: "Optional per-host telemetry to a self-hosted fleet collector."),
        .init(id: "deception", name: "Honeyfile deception",
              category: "prevention", maturity: .optIn,
              summary: "Plants canary credential files. Requires MACCRAB_DECEPTION=1."),
    ]

    /// Filter helper for the About panel.
    public static func by(maturity: ModuleMaturity) -> [ModuleStatus] {
        catalog.filter { $0.maturity == maturity }
    }

    public static func by(category: String) -> [ModuleStatus] {
        catalog.filter { $0.category == category }
    }
}
