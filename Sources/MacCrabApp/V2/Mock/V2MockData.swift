// V2MockData.swift
// Phase 2 mock-data layer — realistic but fixed sample data for the
// v2 dashboard surfaces. The real data layer in phase 4 swaps these
// out with calls into MacCrabCore stores; the shapes here are the
// UI-facing view models, not the storage models.

import Foundation
import SwiftUI

// MARK: - Severity

public enum V2Severity: String, CaseIterable, Sendable {
    case critical, high, medium, low, info

    /// Localized display label. Pre-fix this returned
    /// `rawValue.capitalized` which is English-locked
    /// (`.capitalized` follows the device locale's casing rules but
    /// the underlying word is still "Critical" / "High" etc.). Now
    /// dispatches through `String(localized:)` so the translator
    /// table in `*.lproj/Localizable.strings` controls the surface.
    public var label: String {
        switch self {
        case .critical: return String(localized: "severity.critical", defaultValue: "Critical")
        case .high:     return String(localized: "severity.high",     defaultValue: "High")
        case .medium:   return String(localized: "severity.medium",   defaultValue: "Medium")
        case .low:      return String(localized: "severity.low",      defaultValue: "Low")
        case .info:     return String(localized: "severity.info",     defaultValue: "Info")
        }
    }
    public var chipKind: V2ChipKind {
        switch self {
        case .critical: return .critical
        case .high: return .high
        case .medium: return .medium
        case .low: return .low
        case .info: return .info
        }
    }
    public var sortOrder: Int {
        switch self {
        case .critical: return 0
        case .high: return 1
        case .medium: return 2
        case .low: return 3
        case .info: return 4
        }
    }
}

// MARK: - Status level (orthogonal to severity — used for health / trust /
// feed status surfaces that aren't really severity-ranked).

public enum V2StatusLevel: String, Sendable {
    case healthy, info, warning, critical

    public var label: String {
        switch self {
        case .healthy:  return String(localized: "statusLevel.healthy",  defaultValue: "Healthy")
        case .info:     return String(localized: "statusLevel.info",     defaultValue: "Info")
        case .warning:  return String(localized: "statusLevel.warning",  defaultValue: "Warning")
        case .critical: return String(localized: "statusLevel.critical", defaultValue: "Critical")
        }
    }
    public var chipKind: V2ChipKind {
        switch self {
        case .healthy:  return .healthy
        case .info:     return .info
        case .warning:  return .warning
        case .critical: return .critical
        }
    }
}

// MARK: - Alert

public struct V2MockAlert: Identifiable, Sendable, Hashable {
    public let id: String
    public let title: String
    public let severity: V2Severity
    public let ruleId: String
    public let process: String
    public let processPath: String
    public let pid: Int32
    public let parent: String
    public let user: String
    // v1.12.6 Wave 9H: surface Wave-2 alerts.db schema additions
    // in the alert inspector. Defaults to `""` so the existing
    // V2MockAlert fixture constructors elsewhere in this file don't
    // need to pass them (the inspector rendering hides empty rows).
    public var aiTool: String = ""
    public var workingDirectory: String = ""
    public var processSHA256: String = ""
    public var hostName: String = ""
    // v1.17.2: JSON array of the triggering event(s) snapshotted onto the
    // alert (AlertStore schema v6). Survives events.db pruning so the
    // inspector can show what fired even on an old alert. "" when absent.
    public var triggeringEventsJson: String = ""
    public let timestamp: Date
    public let mitre: [String]
    public let category: String
    public let description: String
    public let actionsTaken: [String]
    // v1.12.7 Wave 9Q: optimistic UI on suppress/unsuppress flips this
    // flag locally before the daemon round-trip completes, so it must
    // be mutable. Previously `let` because the dashboard treated alerts
    // as immutable snapshots — the same-tick reload was the only path
    // by which `suppressed` could change. Now we flip locally first,
    // reload reconciles later.
    public var suppressed: Bool
    // v1.10.0 enrichments — surfaced in the alert inspector. Optional
    // because legacy alerts (pre-Phase-1 enrichment) won't have them
    // and the inspector hides each section when the field is nil/empty.
    public let remediationHint: String?
    public let d3fendTechniques: [String]
    public let llmVerdict: String?       // "true_positive" / "benign" / "needs_human" / "uncertain"
    public let llmConfidence: Double?    // 0.0–1.0
    public let llmSummary: String?       // 2-4 sentence analyst-facing summary
    public let llmModel: String?         // e.g. "claude-sonnet-4-6"
    public let llmSuggestedActions: [String]  // pretty-printed action labels
    public let analystNote: String?
    public let analystOwner: String?
    public let analystStatus: String?    // "new" / "investigating" / "resolved" / "false_positive" / "dismissed"
    public let analystTicketRef: String?

    public init(id: String, title: String, severity: V2Severity, ruleId: String,
                process: String, processPath: String, pid: Int32,
                parent: String, user: String,
                // v1.12.6 Wave 9H additions (default to "" so existing
                // mock fixture call sites stay valid).
                aiTool: String = "",
                workingDirectory: String = "",
                processSHA256: String = "",
                hostName: String = "",
                triggeringEventsJson: String = "",
                timestamp: Date,
                mitre: [String], category: String, description: String,
                actionsTaken: [String], suppressed: Bool,
                remediationHint: String? = nil,
                d3fendTechniques: [String] = [],
                llmVerdict: String? = nil,
                llmConfidence: Double? = nil,
                llmSummary: String? = nil,
                llmModel: String? = nil,
                llmSuggestedActions: [String] = [],
                analystNote: String? = nil,
                analystOwner: String? = nil,
                analystStatus: String? = nil,
                analystTicketRef: String? = nil) {
        self.id = id
        self.title = title
        self.severity = severity
        self.ruleId = ruleId
        self.process = process
        self.processPath = processPath
        self.pid = pid
        self.parent = parent
        self.user = user
        self.aiTool = aiTool
        self.workingDirectory = workingDirectory
        self.processSHA256 = processSHA256
        self.hostName = hostName
        self.triggeringEventsJson = triggeringEventsJson
        self.timestamp = timestamp
        self.mitre = mitre
        self.category = category
        self.description = description
        self.actionsTaken = actionsTaken
        self.suppressed = suppressed
        self.remediationHint = remediationHint
        self.d3fendTechniques = d3fendTechniques
        self.llmVerdict = llmVerdict
        self.llmConfidence = llmConfidence
        self.llmSummary = llmSummary
        self.llmModel = llmModel
        self.llmSuggestedActions = llmSuggestedActions
        self.analystNote = analystNote
        self.analystOwner = analystOwner
        self.analystStatus = analystStatus
        self.analystTicketRef = analystTicketRef
    }
}

// MARK: - Campaign

public struct V2MockCampaign: Identifiable, Sendable, Hashable {
    public let id: String
    public let name: String
    public let severity: V2Severity
    public let firstSeen: Date
    public let lastSeen: Date
    public let alertCount: Int
    public let tactics: [String]
    public let entities: Int
    public let killChainStages: [String]
    public let summary: String
    // v1.12.6 Wave 9J: surface Wave-2 campaigns.db schema additions
    // (v1 → v2 added 7 indexed columns). Defaults to empty so the
    // existing V2MockCampaign fixture constructors stay valid and
    // the inspector hides rows when empty.
    public var affectedUsers: [String] = []
    public var affectedExecutables: [String] = []
    public var techniques: [String] = []
    public var aiTools: [String] = []
    public var processTreeDepth: Int = 0
    /// Whether this campaign is currently suppressed. Drives the
    /// "Suppressed campaigns" restore surface. Defaults false.
    public var suppressed: Bool = false
}

// MARK: - Event

public struct V2MockEvent: Identifiable, Sendable, Hashable {
    public let id: String
    public let timestamp: Date
    public let category: String
    public let process: String
    public let pid: Int32
    public let detail: String
    public let scoring: V2Severity?
}

// MARK: - Rule

public struct V2MockRule: Identifiable, Sendable, Hashable {
    public let id: String
    public let title: String
    public let category: String
    public let severity: V2Severity
    public let mitre: [String]
    public let isEnabled: Bool
    public let lastFired: Date?
    public let firesLastWeek: Int
    public let isCustom: Bool
    public let description: String
    /// Original Sigma status (stable / test / experimental / deprecated). nil
    /// when unknown. Lets the Detection UI label deprecated rules distinctly
    /// from user-disabled ones. Defaulted so existing call sites are unchanged.
    public let status: String?

    /// Operator's severity override for a built-in detection, as a lowercase
    /// Severity raw value ("critical", "high", … matching the inspector
    /// Picker tags). nil when no override is set (the detection runs at its
    /// default severity). Lets the inspector seed its Picker to the live
    /// override instead of always showing "Default". Only populated for
    /// built-in (maccrab.*) rows; nil for Sigma/composite rules.
    public let severityOverrideRaw: String?

    /// True when the rule is parked as deprecated content (ships disabled).
    public var isDeprecated: Bool { status?.lowercased() == "deprecated" }

    public init(id: String, title: String, category: String, severity: V2Severity,
                mitre: [String], isEnabled: Bool, lastFired: Date?, firesLastWeek: Int,
                isCustom: Bool, description: String, status: String? = nil,
                severityOverrideRaw: String? = nil) {
        self.id = id
        self.title = title
        self.category = category
        self.severity = severity
        self.mitre = mitre
        self.isEnabled = isEnabled
        self.lastFired = lastFired
        self.firesLastWeek = firesLastWeek
        self.isCustom = isCustom
        self.description = description
        self.status = status
        self.severityOverrideRaw = severityOverrideRaw
    }
}

// MARK: - Trace (TraceGraph)

public struct V2MockTrace: Identifiable, Sendable, Hashable {
    public let id: String
    public let title: String
    public let rootProcess: String
    public let nodeCount: Int
    public let edgeCount: Int
    public let anchorVerdict: String
    public let firstSeen: Date
    public let lastUpdated: Date
    public let isDemo: Bool
    public let severityHint: V2Severity
}

// MARK: - Agent session (Wave-3 recorder)

/// One AI-coding-agent session's summary for the dashboard list.
public struct V2AgentSession: Identifiable, Sendable, Hashable {
    public let id: String          // durable session id
    public let tool: String
    public let projectDir: String?
    public let eventCount: Int
    public let firstSeen: Date
    public let lastSeen: Date

    public init(id: String, tool: String, projectDir: String?, eventCount: Int, firstSeen: Date, lastSeen: Date) {
        self.id = id
        self.tool = tool
        self.projectDir = projectDir
        self.eventCount = eventCount
        self.firstSeen = firstSeen
        self.lastSeen = lastSeen
    }
}

// MARK: - Threat intel feed

public struct V2MockFeed: Identifiable, Sendable, Hashable {
    public let id: String
    public let name: String
    public let kind: String
    public let entries: Int
    public let lastFetch: Date
    public let status: V2StatusLevel
    public let staleness: TimeInterval
    /// Most recent feed-update failure reason, if any (e.g.
    /// "HTTP 503" or "0 records parsed (empty feed)"). nil when the
    /// feed's last attempt succeeded. Surfaced so a frozen IOC count
    /// reads as a visible error instead of a silent stall.
    public var lastError: String? = nil
}

// MARK: - Browser extension

public struct V2MockExtension: Identifiable, Sendable, Hashable {
    public let id: String
    public let name: String
    public let browser: String
    public let version: String
    public let permissions: [String]
    public let signed: Bool
    public let riskScore: Int
    public let installedAt: Date
}

// MARK: - MCP server

public struct V2MockMCP: Identifiable, Sendable, Hashable {
    public let id: String
    public let name: String
    public let host: String
    public let toolCount: Int
    public let knownTo: [String]   // e.g. "Claude Code", "Cursor"
    public let trust: V2StatusLevel
    public let lastUsed: Date
}

// MARK: - Collector health

public struct V2MockCollector: Identifiable, Sendable, Hashable {
    public let id: String
    public let name: String
    public let status: V2StatusLevel
    public let throughput: Double      // events / sec
    public let lag: TimeInterval       // approx
    public let errors: Int
    public let lastEvent: Date
}

// MARK: - TCC permission

public struct V2MockPermission: Identifiable, Sendable, Hashable {
    public let id: String
    public let service: String
    public let granted: Bool
    public let required: Bool
    public let description: String
}

// MARK: - Package freshness

public struct V2MockPackage: Identifiable, Sendable, Hashable {
    public let id: String
    public let name: String
    public let installed: String
    public let latest: String
    public let manager: String
    public let vulnCount: Int
    public let staleness: TimeInterval
    // v1.12.0 supply-chain intelligence fields — optional so older
    // mock fixtures and PackageFreshnessChecker results still compile.
    public let typosquatScore: Int?
    public let typosquatSimilarTo: String?
    public let isLikelyTyposquat: Bool
    public let attestationStatus: String?
    public let contentRedFlags: [String]?

    public init(
        id: String, name: String, installed: String, latest: String,
        manager: String, vulnCount: Int, staleness: TimeInterval,
        typosquatScore: Int? = nil,
        typosquatSimilarTo: String? = nil,
        attestationStatus: String? = nil,
        contentRedFlags: [String]? = nil
    ) {
        self.id = id
        self.name = name
        self.installed = installed
        self.latest = latest
        self.manager = manager
        self.vulnCount = vulnCount
        self.staleness = staleness
        self.typosquatScore = typosquatScore
        self.typosquatSimilarTo = typosquatSimilarTo
        self.isLikelyTyposquat = (typosquatScore ?? 0) >= 80
        self.attestationStatus = attestationStatus
        self.contentRedFlags = contentRedFlags
    }
}

// MARK: - Integration

/// v1.11.1: minimal integration descriptor for the Intelligence →
/// Integrations panel. Surfaces the operator's configured external
/// sinks (webhook destinations, SIEM endpoints, file outputs,
/// object stores). `status` is "configured" until per-sink health
/// reporting lands in v1.11.x — at which point we'll distinguish
/// healthy / degraded / failing.
public struct V2MockIntegration: Identifiable, Sendable, Hashable {
    public let id: String
    public let name: String
    public let kind: String          // "webhook" / "siem" / "file" / "object-store" / "notification"
    public let status: V2StatusLevel
    public let detail: String
    public init(id: String, name: String, kind: String, status: V2StatusLevel, detail: String) {
        self.id = id
        self.name = name
        self.kind = kind
        self.status = status
        self.detail = detail
    }
}

// MARK: - Repository

public enum V2MockRepository {

    public static let alerts: [V2MockAlert] = [
        .init(id: "alt-001", title: "Suspicious shell spawn from launchd plist",
              severity: .critical, ruleId: "persistence_launchd_plist_shell_spawn",
              process: "bash", processPath: "/bin/bash",
              pid: 8821, parent: "launchd", user: "ph",
              timestamp: now(-9 * 60),
              mitre: ["T1543.001", "T1059.004"],
              category: "Persistence",
              description: "A LaunchAgent/Daemon plist directly invoked /bin/bash with -c. Suggests interactive persistence rather than a normal service binary.",
              actionsTaken: ["alerted", "process_recorded"],
              suppressed: false),
        .init(id: "alt-002", title: "Codex CLI wrote .env outside expected scope",
              severity: .high, ruleId: "ai_guard_codex_secret_write",
              process: "codex", processPath: "/usr/local/bin/codex",
              pid: 8822, parent: "iTerm2", user: "ph",
              timestamp: now(-22 * 60),
              mitre: ["T1530"],
              category: "AI Guard",
              description: "Codex agent wrote a .env file in a project directory it has not previously touched. Lineage shows agent → bash → tee.",
              actionsTaken: ["alerted"],
              suppressed: false),
        .init(id: "alt-003", title: "Browser extension requested all_urls + tabs + cookies",
              severity: .high, ruleId: "browser_extension_high_risk_perms",
              process: "Chrome", processPath: "/Applications/Google Chrome.app",
              pid: 412, parent: "launchd", user: "ph",
              timestamp: now(-44 * 60),
              mitre: ["T1176"],
              category: "Browser",
              description: "Recently installed Chrome extension declares <all_urls>, tabs, and cookies — high theft risk surface for an unsigned publisher.",
              actionsTaken: ["alerted"],
              suppressed: false),
        .init(id: "alt-004", title: "Defender Safari ad-blocker requested broad host permissions",
              severity: .medium, ruleId: "browser_extension_broad_host_perms",
              process: "Safari", processPath: "/Applications/Safari.app",
              pid: 510, parent: "launchd", user: "ph",
              timestamp: now(-63 * 60),
              mitre: ["T1176"],
              category: "Browser",
              description: "Safari extension declares wildcard host permissions. Lower confidence — popular vendor and notarized.",
              actionsTaken: ["alerted"],
              suppressed: false),
        .init(id: "alt-005", title: "Unsigned binary spawned from /tmp",
              severity: .high, ruleId: "exec_unsigned_binary_from_tmp",
              process: "loader", processPath: "/tmp/.x/loader",
              pid: 9912, parent: "bash", user: "ph",
              timestamp: now(-2 * 60 * 60),
              mitre: ["T1059", "T1027"],
              category: "Execution",
              description: "Unsigned Mach-O loaded from /tmp; CDHash unknown to allowlist; spawned by an interactive shell.",
              actionsTaken: ["alerted", "process_recorded", "watchlisted"],
              suppressed: false),
        .init(id: "alt-006", title: "Outbound connection to known C2 IP (203.0.113.42)",
              severity: .critical, ruleId: "intel_c2_match",
              process: "loader", processPath: "/tmp/.x/loader",
              pid: 9912, parent: "bash", user: "ph",
              timestamp: now(-2 * 60 * 60 + 4),
              mitre: ["T1071.001"],
              category: "C2",
              description: "Outbound TCP/443 to an IP currently flagged by 2 of 5 intel sources as Lazarus stage-1.",
              actionsTaken: ["alerted", "blocked"],
              suppressed: false),
        .init(id: "alt-007", title: "MCP server tool count grew suddenly (+12)",
              severity: .medium, ruleId: "mcp_tool_inflation",
              process: "claude", processPath: "/usr/local/bin/claude",
              pid: 5523, parent: "iTerm2", user: "ph",
              timestamp: now(-3 * 60 * 60),
              mitre: ["T1059"],
              category: "AI Guard",
              description: "An MCP server known to Claude Code went from 4 to 16 tools without a config change. Possible supply-chain or remote prompt-injection exposure.",
              actionsTaken: ["alerted"],
              suppressed: false),
        .init(id: "alt-008", title: "TCC change: Full Disk Access granted to new app",
              severity: .high, ruleId: "tcc_fda_grant",
              process: "tccd", processPath: "/usr/libexec/tccd",
              pid: 217, parent: "launchd", user: "ph",
              timestamp: now(-5 * 60 * 60),
              mitre: ["T1546"],
              category: "TCC",
              description: "Full Disk Access granted to /Applications/RemoteWorker.app. App is notarized but is new on this device.",
              actionsTaken: ["alerted"],
              suppressed: false),
        .init(id: "alt-009", title: "Clipboard exfil pattern: 3 password-shaped reads in 4s",
              severity: .medium, ruleId: "clipboard_exfil_burst",
              process: "loader", processPath: "/tmp/.x/loader",
              pid: 9912, parent: "bash", user: "ph",
              timestamp: now(-2 * 60 * 60 + 30),
              mitre: ["T1115"],
              category: "Collection",
              description: "Three consecutive reads of clipboard content matching credential patterns from a process under suspicion.",
              actionsTaken: ["alerted"],
              suppressed: false),
        .init(id: "alt-010", title: "Honeyfile read: ~/.aws/credentials.canary",
              severity: .critical, ruleId: "honeyfile_credential_read",
              process: "loader", processPath: "/tmp/.x/loader",
              pid: 9912, parent: "bash", user: "ph",
              timestamp: now(-2 * 60 * 60 + 36),
              mitre: ["T1552.001"],
              category: "Credential Access",
              description: "Canary AWS credentials file was read by a recently-watchlisted process. There is no legitimate reason to read this file.",
              actionsTaken: ["alerted", "killed"],
              suppressed: false),
        .init(id: "alt-011", title: "USB mass storage attached: VendorID 0x1234",
              severity: .low, ruleId: "usb_attach",
              process: "kernel", processPath: "/kernel",
              pid: 0, parent: "kernel", user: "system",
              timestamp: now(-7 * 60 * 60),
              mitre: ["T1200"],
              category: "USB",
              description: "An external USB storage device was attached. Recorded for context.",
              actionsTaken: ["alerted"],
              suppressed: true),
        .init(id: "alt-012", title: "Periodic baseline: novel process lineage",
              severity: .low, ruleId: "baseline_novel_lineage",
              process: "ffmpeg", processPath: "/opt/homebrew/bin/ffmpeg",
              pid: 13044, parent: "Final Cut Pro", user: "ph",
              timestamp: now(-10 * 60 * 60),
              mitre: [],
              category: "Baseline",
              description: "Lineage Final Cut Pro → ffmpeg has not been seen on this device before. Likely a benign first-time render path.",
              actionsTaken: ["alerted"],
              suppressed: false),
    ]

    public static let campaigns: [V2MockCampaign] = [
        .init(id: "cmp-001", name: "Lazarus stage-1 dropper",
              severity: .critical,
              firstSeen: now(-2 * 60 * 60),
              lastSeen: now(-30 * 60),
              alertCount: 7,
              tactics: ["Initial Access", "Execution", "Defense Evasion", "Credential Access", "C2"],
              entities: 4,
              killChainStages: ["Recon", "Delivery", "Exploit", "Install", "C2", "Action"],
              summary: "Loader from /tmp → C2 beacon → honeyfile read → clipboard burst. Killed at honeyfile."),
        .init(id: "cmp-002", name: "AI Guard: Codex agent file write spree",
              severity: .high,
              firstSeen: now(-30 * 60),
              lastSeen: now(-9 * 60),
              alertCount: 3,
              tactics: ["AI Guard"],
              entities: 1,
              killChainStages: ["Tool use"],
              summary: "Codex CLI wrote 14 files outside its previous scope, including 1 .env. Lineage rooted at iTerm2 → codex → bash → tee."),
        .init(id: "cmp-003", name: "Browser extension over-permission cluster",
              severity: .medium,
              firstSeen: now(-2 * 24 * 60 * 60),
              lastSeen: now(-44 * 60),
              alertCount: 4,
              tactics: ["Browser"],
              entities: 2,
              killChainStages: ["Install"],
              summary: "Two recently-installed extensions across Chrome and Safari requested broad permissions within a 48h window."),
    ]

    public static let events: [V2MockEvent] = (0..<60).map { i in
        let categories = ["process", "file", "network", "tcc", "ai_guard", "browser", "log"]
        return .init(
            id: "evt-\(String(format: "%04d", i))",
            timestamp: now(Double(-i * 12)),
            category: categories[i % categories.count],
            process: ["bash", "Chrome", "claude", "codex", "fseventsd", "syslogd"][i % 6],
            pid: Int32(8000 + i),
            detail: ["read /etc/hosts", "TCP connect 1.1.1.1:443", "spawn",
                     "wrote ~/.cache/x", "log: kext load",
                     "exec cargo build", "DNS api.github.com"][i % 7],
            scoring: i % 9 == 0 ? .high : (i % 5 == 0 ? .medium : nil)
        )
    }

    public static let rules: [V2MockRule] = [
        .init(id: "persistence_launchd_plist_shell_spawn",
              title: "LaunchAgent / Daemon plist invokes shell directly",
              category: "Persistence",
              severity: .high,
              mitre: ["T1543.001"],
              isEnabled: true, lastFired: now(-9 * 60), firesLastWeek: 4,
              isCustom: false,
              description: "Detects launchd plist that invokes /bin/sh or /bin/bash with -c, indicating interactive persistence rather than a real service binary."),
        .init(id: "ai_guard_codex_secret_write",
              title: "AI agent wrote .env / credentials outside known scope",
              category: "AI Guard",
              severity: .high,
              mitre: ["T1530"],
              isEnabled: true, lastFired: now(-22 * 60), firesLastWeek: 3,
              isCustom: false,
              description: "AI coding tool process wrote a credentials-shaped file outside its previously-observed working set."),
        .init(id: "intel_c2_match",
              title: "Outbound to known-bad C2 IP",
              category: "C2",
              severity: .critical,
              mitre: ["T1071.001"],
              isEnabled: true, lastFired: now(-2 * 60 * 60), firesLastWeek: 1,
              isCustom: false,
              description: "Process opened TCP connection to an IP listed in the active threat-intel feed cohort."),
        .init(id: "exec_unsigned_binary_from_tmp",
              title: "Unsigned Mach-O executed from /tmp",
              category: "Execution",
              severity: .high,
              mitre: ["T1059", "T1027"],
              isEnabled: true, lastFired: now(-2 * 60 * 60), firesLastWeek: 1,
              isCustom: false,
              description: "Unsigned binary loaded from a world-writable directory by an interactive shell."),
        .init(id: "honeyfile_credential_read",
              title: "Honeyfile credential read",
              category: "Credential Access",
              severity: .critical,
              mitre: ["T1552.001"],
              isEnabled: true, lastFired: now(-2 * 60 * 60), firesLastWeek: 1,
              isCustom: false,
              description: "Process read a deception canary credentials file. There is no legitimate reason to read this path."),
        .init(id: "tcc_fda_grant",
              title: "Full Disk Access granted to non-allowlisted app",
              category: "TCC",
              severity: .high,
              mitre: ["T1546"],
              isEnabled: true, lastFired: now(-5 * 60 * 60), firesLastWeek: 2,
              isCustom: false,
              description: "TCC database recorded a Full Disk Access grant to an application not on the device's allowlist."),
        .init(id: "browser_extension_high_risk_perms",
              title: "Browser extension requested high-risk permissions",
              category: "Browser",
              severity: .medium,
              mitre: ["T1176"],
              isEnabled: true, lastFired: now(-44 * 60), firesLastWeek: 5,
              isCustom: false,
              description: "Extension declares <all_urls>, tabs, cookies, or webRequestBlocking — broad theft surface."),
        .init(id: "mcp_tool_inflation",
              title: "MCP server tool count grew without config change",
              category: "AI Guard",
              severity: .medium,
              mitre: ["T1059"],
              isEnabled: true, lastFired: now(-3 * 60 * 60), firesLastWeek: 1,
              isCustom: false,
              description: "An MCP server's exposed tool count increased significantly between checks despite no config delta."),
        .init(id: "custom_after_hours_admin",
              title: "After-hours admin command [custom]",
              category: "Custom",
              severity: .low,
              mitre: ["T1059"],
              isEnabled: true, lastFired: nil, firesLastWeek: 0,
              isCustom: true,
              description: "Locally-authored rule: sudo / launchctl / pmset commands invoked outside business hours."),
    ]

    public static let traces: [V2MockTrace] = [
        .init(id: "trc-001",
              title: "[DEMO] Lazarus stage-1 simulation",
              rootProcess: "iTerm2 → bash → loader",
              nodeCount: 41, edgeCount: 56,
              anchorVerdict: "loader (suspicious)",
              firstSeen: now(-2 * 60 * 60), lastUpdated: now(-30 * 60),
              isDemo: true, severityHint: .critical),
        .init(id: "trc-002",
              title: "[DEMO] Codex agent file write spree",
              rootProcess: "iTerm2 → codex → bash",
              nodeCount: 18, edgeCount: 22,
              anchorVerdict: "codex (high)",
              firstSeen: now(-30 * 60), lastUpdated: now(-9 * 60),
              isDemo: true, severityHint: .high),
        .init(id: "trc-003",
              title: "Build pipeline (Final Cut Pro render)",
              rootProcess: "Final Cut Pro → ffmpeg",
              nodeCount: 6, edgeCount: 5,
              anchorVerdict: "ffmpeg (benign)",
              firstSeen: now(-10 * 60 * 60), lastUpdated: now(-9 * 60 * 60),
              isDemo: false, severityHint: .low),
    ]

    public static let feeds: [V2MockFeed] = [
        .init(id: "f-1", name: "abuse.ch URLhaus", kind: "URL list",
              entries: 121_438, lastFetch: now(-12 * 60), status: .info, staleness: 12 * 60),
        .init(id: "f-2", name: "abuse.ch ThreatFox", kind: "IOC feed",
              entries: 84_220, lastFetch: now(-18 * 60), status: .info, staleness: 18 * 60),
        .init(id: "f-3", name: "Spamhaus DROP", kind: "Network blocklist",
              entries: 1_044, lastFetch: now(-30 * 60), status: .info, staleness: 30 * 60),
        .init(id: "f-4", name: "Internal allowlist", kind: "Custom",
              entries: 412, lastFetch: now(-2 * 60), status: .healthy, staleness: 2 * 60),
        .init(id: "f-5", name: "MITRE ATT&CK enterprise", kind: "Tactic mapping",
              entries: 723, lastFetch: now(-24 * 60 * 60), status: .info, staleness: 24 * 60 * 60),
        .init(id: "f-6", name: "VirusTotal", kind: "Hash lookup",
              entries: 0, lastFetch: now(-7 * 24 * 60 * 60), status: .warning, staleness: 7 * 24 * 60 * 60),
    ]

    public static let extensions: [V2MockExtension] = [
        .init(id: "x-1", name: "1Password – Password Manager", browser: "Chrome",
              version: "8.10.36", permissions: ["activeTab", "storage", "<all_urls>"],
              signed: true, riskScore: 22,
              installedAt: now(-90 * 24 * 60 * 60)),
        .init(id: "x-2", name: "uBlock Origin", browser: "Firefox",
              version: "1.55.0", permissions: ["webRequest", "webRequestBlocking", "<all_urls>"],
              signed: true, riskScore: 35,
              installedAt: now(-120 * 24 * 60 * 60)),
        .init(id: "x-3", name: "ColorTabs Pro", browser: "Chrome",
              version: "2.1.4", permissions: ["tabs", "cookies", "<all_urls>"],
              signed: false, riskScore: 78,
              installedAt: now(-44 * 60)),
        .init(id: "x-4", name: "DefenderBlocker", browser: "Safari",
              version: "1.0.7", permissions: ["websites.*"],
              signed: true, riskScore: 51,
              installedAt: now(-3 * 24 * 60 * 60)),
        .init(id: "x-5", name: "GitHub Code Folding", browser: "Brave",
              version: "0.4.2", permissions: ["activeTab"],
              signed: true, riskScore: 12,
              installedAt: now(-30 * 24 * 60 * 60)),
    ]

    public static let mcpServers: [V2MockMCP] = [
        .init(id: "m-1", name: "filesystem", host: "localhost", toolCount: 8,
              knownTo: ["Claude Code", "Cursor"], trust: .info, lastUsed: now(-15 * 60)),
        .init(id: "m-2", name: "github", host: "localhost", toolCount: 14,
              knownTo: ["Claude Code"], trust: .info, lastUsed: now(-5 * 60)),
        .init(id: "m-3", name: "maccrab-mcp", host: "localhost", toolCount: 7,
              knownTo: ["Claude Code"], trust: .healthy, lastUsed: now(-2 * 60)),
        .init(id: "m-4", name: "supplychain-tools", host: "localhost", toolCount: 16,
              knownTo: ["Claude Code"], trust: .warning, lastUsed: now(-3 * 60 * 60)),
    ]

    public static let collectors: [V2MockCollector] = [
        .init(id: "c-1", name: "EndpointSecurity", status: .healthy,
              throughput: 425, lag: 0.05, errors: 0, lastEvent: now(-1)),
        .init(id: "c-2", name: "UnifiedLog", status: .healthy,
              throughput: 1_120, lag: 0.5, errors: 0, lastEvent: now(-2)),
        .init(id: "c-3", name: "Network", status: .healthy,
              throughput: 86, lag: 1.2, errors: 0, lastEvent: now(-3)),
        .init(id: "c-4", name: "DNS (BPF)", status: .healthy,
              throughput: 22, lag: 0.4, errors: 0, lastEvent: now(-2)),
        .init(id: "c-5", name: "TCC", status: .healthy,
              throughput: 0.4, lag: 60, errors: 0, lastEvent: now(-90)),
        .init(id: "c-6", name: "EDRMonitor", status: .healthy,
              throughput: 0.01, lag: 120, errors: 0, lastEvent: now(-120)),
        .init(id: "c-7", name: "MCPMonitor", status: .info,
              throughput: 0.0, lag: 600, errors: 0, lastEvent: now(-600)),
        .init(id: "c-8", name: "Clipboard", status: .healthy,
              throughput: 0.5, lag: 2, errors: 0, lastEvent: now(-30)),
        .init(id: "c-9", name: "USB", status: .healthy,
              throughput: 0.0, lag: 10, errors: 0, lastEvent: now(-7 * 60 * 60)),
        .init(id: "c-10", name: "TEMPEST", status: .healthy,
              throughput: 0.0, lag: 60, errors: 0, lastEvent: now(-12 * 60 * 60)),
    ]

    public static let permissions: [V2MockPermission] = [
        .init(id: "p-1", service: "Full Disk Access", granted: true, required: true,
              description: "Required for SQLite event store, /Library inspection, and quarantine reads."),
        .init(id: "p-2", service: "Endpoint Security entitlement", granted: true, required: true,
              description: "Required for the system extension to receive process / file / auth events."),
        .init(id: "p-3", service: "Notifications", granted: true, required: false,
              description: "Allows MacCrab to surface alerts as macOS notifications."),
        .init(id: "p-4", service: "Microphone", granted: false, required: false,
              description: "Required only for the optional ultrasonic / NUIT detector. Off by default."),
        .init(id: "p-5", service: "Accessibility", granted: false, required: false,
              description: "Optional — used by the EventTap keylogger heuristic. Off by default."),
        .init(id: "p-6", service: "Bluetooth", granted: true, required: false,
              description: "Used by Bluetooth subsystem log collector."),
    ]

    public static let packages: [V2MockPackage] = [
        .init(id: "pk-1", name: "openssl", installed: "3.2.0", latest: "3.2.1",
              manager: "brew", vulnCount: 1, staleness: 14 * 24 * 60 * 60),
        .init(id: "pk-2", name: "node", installed: "20.10.0", latest: "20.11.1",
              manager: "brew", vulnCount: 0, staleness: 30 * 24 * 60 * 60),
        .init(id: "pk-3", name: "git", installed: "2.43.0", latest: "2.43.0",
              manager: "brew", vulnCount: 0, staleness: 0),
        .init(id: "pk-4", name: "python@3.11", installed: "3.11.5", latest: "3.11.7",
              manager: "brew", vulnCount: 0, staleness: 60 * 24 * 60 * 60),
        .init(id: "pk-5", name: "ffmpeg", installed: "6.1", latest: "6.1.1",
              manager: "brew", vulnCount: 0, staleness: 7 * 24 * 60 * 60),
        .init(id: "pk-6", name: "react", installed: "18.2.0", latest: "18.3.1",
              manager: "npm", vulnCount: 2, staleness: 21 * 24 * 60 * 60),
        .init(id: "pk-7", name: "express", installed: "4.18.2", latest: "4.19.2",
              manager: "npm", vulnCount: 1, staleness: 14 * 24 * 60 * 60),
    ]

    private static func now(_ deltaSeconds: Double) -> Date {
        Date().addingTimeInterval(deltaSeconds)
    }
}

// MARK: - Time formatting helpers

public enum V2TimeFormat {
    public static func relative(_ date: Date) -> String {
        let interval = -date.timeIntervalSinceNow
        if interval < 60          { return "\(Int(interval))s ago" }
        if interval < 60 * 60     { return "\(Int(interval / 60))m ago" }
        if interval < 24 * 60 * 60 { return "\(Int(interval / 3600))h ago" }
        return "\(Int(interval / 86400))d ago"
    }
    public static func absolute(_ date: Date) -> String {
        let f = DateFormatter()
        f.dateFormat = "yyyy-MM-dd HH:mm:ss"
        return f.string(from: date)
    }
    public static func short(_ date: Date) -> String {
        let f = DateFormatter()
        f.dateFormat = "HH:mm:ss"
        return f.string(from: date)
    }
    public static func staleness(_ seconds: TimeInterval) -> String {
        if seconds < 60          { return "<1m" }
        if seconds < 60 * 60     { return "\(Int(seconds / 60))m" }
        if seconds < 24 * 60 * 60 { return "\(Int(seconds / 3600))h" }
        return "\(Int(seconds / 86400))d"
    }
}
