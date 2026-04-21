// DocsView.swift
// MacCrabApp

import SwiftUI

struct DocsView: View {
    @State private var selectedSection: DocSection = .overview

    enum DocSection: String, CaseIterable, Identifiable {
        case overview = "Overview"
        case architecture = "How It Works"
        case detections = "What It Detects"
        case alerts = "When a Detection Fires"
        case rules = "Creating Rules"
        case actions = "Response Actions"
        case cli = "CLI Reference"
        case shortcuts = "Keyboard Shortcuts"
        case tuning = "Tuning & Allowlists"

        var id: String { rawValue }
        var icon: String {
            switch self {
            case .overview:     return "shield.checkered"
            case .architecture: return "cpu"
            case .detections:   return "shield.checkered"
            case .alerts:       return "exclamationmark.triangle"
            case .rules:        return "plus.rectangle"
            case .actions:      return "bolt.shield"
            case .cli:          return "terminal"
            case .shortcuts:    return "keyboard"
            case .tuning:       return "slider.horizontal.3"
            }
        }
    }

    var body: some View {
        HSplitView {
            // Sidebar
            List(DocSection.allCases, selection: $selectedSection) { section in
                Label(section.rawValue, systemImage: section.icon)
                    .tag(section)
            }
            .frame(minWidth: 180, idealWidth: 200, maxWidth: 220)

            // Content
            ScrollView {
                VStack(alignment: .leading, spacing: 0) {
                    content(for: selectedSection)
                }
                .padding(24)
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
    }

    @ViewBuilder
    private func content(for section: DocSection) -> some View {
        switch section {
        case .overview:     overviewContent
        case .architecture: architectureContent
        case .detections:   detectionsContent
        case .alerts:       alertsContent
        case .rules:        rulesContent
        case .actions:      actionsContent
        case .cli:          cliContent
        case .shortcuts:    shortcutsContent
        case .tuning:       tuningContent
        }
    }

    private var shortcutsContent: some View {
        VStack(alignment: .leading, spacing: 16) {
            DocTitle("Keyboard Shortcuts")
            DocBody("The dashboard and status-bar menu accept these shortcuts. Menubar shortcuts fire only while the menu is open.")

            DocSubtitle("Status-bar menu")
            keyRow("⌘D", "Open Dashboard")
            keyRow("⌘R", "Reload Rules")
            keyRow("⌘F", "Refresh data")
            keyRow("⌘,", "Settings")
            keyRow("⌘Q", "Quit MacCrab")

            DocSubtitle("Alerts tab")
            keyRow("⌘A", "Select all visible alerts")
            keyRow("⌘Z", "Undo last suppress")
            keyRow("⌘E", "Export alerts (JSON / CSV / SIEM formats)")
            keyRow("⌘R", "Refresh")

            DocSubtitle("Campaigns tab")
            keyRow("Delete", "Dismiss selected campaigns (in Select mode)")
            keyRow("Escape", "Cancel selection mode")

            DocSubtitle("Events tab")
            keyRow("Space", "Pause / resume live stream")
            keyRow("⌘R", "Refresh")

            DocSubtitle("Alert detail")
            keyRow("Return", "Submit text field (e.g. AI hunt query)")
        }
    }

    private func keyRow(_ shortcut: String, _ description: String) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 12) {
            Text(shortcut)
                .font(.system(.body, design: .monospaced))
                .padding(.vertical, 2).padding(.horizontal, 6)
                .background(Color.secondary.opacity(0.15))
                .cornerRadius(4)
                .frame(minWidth: 80, alignment: .leading)
            Text(description).foregroundColor(.primary)
            Spacer()
        }
    }

    // MARK: - Overview

    private var overviewContent: some View {
        VStack(alignment: .leading, spacing: 16) {
            DocTitle("MacCrab Detection Engine")
            DocBody("""
            MacCrab is a local-first macOS security monitoring tool. It watches what \
            happens on your Mac in real time — process executions, file changes, network \
            connections, and permission grants — and evaluates 304 detection rules against \
            every event to find threats.
            """)

            DocSubtitle("Key Principles")
            DocBullets([
                "Local-first: all detection runs on-device, no cloud dependency",
                "Sigma-compatible: rules use the industry-standard Sigma format",
                "Zero infrastructure: no Elasticsearch, no SIEM, no Docker",
                "Privacy-preserving: your telemetry never leaves your Mac",
            ])

            DocSubtitle("What Makes It Different")
            DocBody("""
            Most macOS security tools either require enterprise cloud infrastructure \
            (CrowdStrike, SentinelOne) or only monitor a single domain (LuLu for \
            firewall, BlockBlock for persistence). MacCrab combines all event sources \
            into one engine with cross-event correlation — detecting multi-step attacks \
            that single-domain tools miss.
            """)

            DocSubtitle("Quick Start")
            DocCode("""
            # Build and run (one command)
            make dev

            # See what's happening
            maccrabctl status
            maccrabctl events tail 20
            maccrabctl alerts 10

            # Live alert stream
            maccrabctl watch
            """)
        }
    }

    // MARK: - Architecture

    private var architectureContent: some View {
        VStack(alignment: .leading, spacing: 16) {
            DocTitle("How It Works")

            DocSubtitle("Event Sources (4)")
            DocBody("MacCrab collects security telemetry from four macOS sources:")

            DocTable(headers: ["Source", "What It Captures", "Requires Root?"], rows: [
                ["Endpoint Security", "Process exec/fork/exit, file create/write/delete/rename, code signing", "Yes"],
                ["Unified Log", "System logs from 12 subsystems (TCC, Gatekeeper, sudo, auth, DNS, firewall)", "No"],
                ["TCC Monitor", "Permission grants and revocations (camera, microphone, screen recording, etc.)", "No"],
                ["Network Collector", "Active TCP/UDP connections per process (polls every 5 seconds)", "No"],
            ])

            DocSubtitle("Enrichment Pipeline")
            DocBody("Every event passes through three enrichment stages before rule evaluation:")
            DocBullets([
                "Process Lineage: builds a parent-child process tree (who spawned whom)",
                "Code Signing: caches and evaluates code signatures (Apple, Developer ID, unsigned)",
                "YARA Scanning: optional file content scanning for malware signatures",
            ])

            DocSubtitle("Detection Layers (3)")
            DocBullets([
                "Single-Event Rules (195): Sigma-compatible rules that match individual events — \"if process X does Y, alert\"",
                "Sequence Rules (20): Temporal-causal rules that detect multi-step attack chains — \"if A happens, then B within 60 seconds, alert\"",
                "Baseline Anomaly: learns normal process-spawning patterns over 7 days, then alerts on novel parent→child relationships",
            ])

            DocSubtitle("Data Flow")
            DocCode("""
            Events → Enrichment → Rule Engine ──→ Alert Store → Dashboard
                                      │              │
                                      │              ├→ Notifications
                                      │              ├→ Response Actions
                                      │              └→ JSONL / Webhook / Syslog
                                      │
                                  Sequence Engine
                                  Baseline Engine
            """)
        }
    }

    // MARK: - Detections

    private var detectionsContent: some View {
        VStack(alignment: .leading, spacing: 16) {
            DocTitle("What It Detects")
            DocBody("304 detection rules across 12 MITRE ATT&CK tactics:")

            DocTable(headers: ["Tactic", "Examples", "Rules"], rows: [
                ["Initial Access", "Exploit payloads, phishing downloads, supply chain attacks", "15"],
                ["Execution", "Reverse shells, osascript abuse, Python/Ruby one-liners", "25"],
                ["Persistence", "LaunchAgents, login items, cron jobs, shell profile mods", "30"],
                ["Privilege Escalation", "sudo abuse, SUID binaries, TCC bypasses", "12"],
                ["Defense Evasion", "Log deletion, Gatekeeper bypass, code injection", "20"],
                ["Credential Access", "Keychain dumps, password manager DB access, credential harvesting", "15"],
                ["Discovery", "System enumeration, network scanning, process listing", "12"],
                ["Lateral Movement", "SSH tunneling, VNC, remote desktop", "8"],
                ["Collection", "Screen recording, microphone access, keylogging", "10"],
                ["Command & Control", "Reverse shells, DNS tunneling, Tor, ngrok, C2 callbacks", "18"],
                ["Exfiltration", "Large file uploads, DNS exfil, archive staging", "8"],
                ["Supply Chain", "VS Code extension attacks, npm/pip package compromise", "15"],
            ])

            DocSubtitle("Sequence Detection (Multi-Step Attacks)")
            DocBody("""
            20 temporal sequence rules detect attack chains that unfold over time. \
            Examples:
            """)
            DocBullets([
                "Download → Execute unsigned → Install persistence → C2 callback (120s window)",
                "Shell spawn from web server → outbound connection (10s window)",
                "Privilege escalation → persistence installation (60s window)",
                "npm/pip install → suspicious post-install script → credential harvest",
            ])
        }
    }

    // MARK: - Alerts

    private var alertsContent: some View {
        VStack(alignment: .leading, spacing: 16) {
            DocTitle("When a Detection Fires")
            DocBody("When a rule matches an event, MacCrab creates an alert and can take several actions:")

            DocSubtitle("Alert Severity Levels")
            DocTable(headers: ["Level", "Meaning", "Default Action"], rows: [
                ["Critical", "Active exploitation or confirmed malicious activity", "Notification + log"],
                ["High", "Strong indicator of compromise, needs investigation", "Notification + log"],
                ["Medium", "Suspicious activity, may be legitimate", "Log only"],
                ["Low", "Informational, unusual but likely benign", "Log only"],
            ])

            DocSubtitle("What Happens Automatically")
            DocBullets([
                "Alert stored in SQLite database (queryable via CLI and dashboard)",
                "macOS notification banner for high and critical alerts",
                "Written to JSONL log file for external ingestion",
                "Response actions executed (if configured — see Response Actions)",
                "Alert deduplicated: same rule + same process suppressed for 1 hour",
            ])

            DocSubtitle("Viewing Alerts")
            DocCode("""
            # Dashboard
            Click the Alerts tab — click any alert for full details

            # CLI
            maccrabctl alerts 20          # last 20 alerts
            maccrabctl watch              # live stream
            maccrabctl export json        # export all alerts as JSON
            maccrabctl export csv 500     # export as CSV
            """)
        }
    }

    // MARK: - Rules

    private var rulesContent: some View {
        VStack(alignment: .leading, spacing: 16) {
            DocTitle("Creating Rules")
            DocBody("""
            MacCrab uses Sigma-compatible YAML rules. You can create custom rules \
            for your specific environment.
            """)

            DocSubtitle("Generate a Template")
            DocCode("""
            # Generate a template for a specific event category
            maccrabctl rule create process_creation
            maccrabctl rule create file_event
            maccrabctl rule create network_connection
            maccrabctl rule create tcc_event
            maccrabctl rule create sequence
            """)

            DocSubtitle("Rule Structure")
            DocCode("""
            title: My Custom Rule
            id: <auto-generated-uuid>
            status: experimental
            description: >
                What this rule detects and why it matters.
            author: Your Name
            date: 2026/04/03
            tags:
                - attack.execution
                - attack.t1059.004
            logsource:
                category: process_creation
                product: macos
            detection:
                selection:
                    Image|endswith: '/suspicious-binary'
                    CommandLine|contains: '--malicious-flag'
                filter_signed:
                    SignerType:
                        - 'apple'
                        - 'devId'
                condition: selection and not filter_signed
            falsepositives:
                - Known legitimate use cases
            level: high
            """)

            DocSubtitle("Available Fields")
            DocTable(headers: ["Category", "Fields"], rows: [
                ["Process", "Image, CommandLine, ParentImage, SignerType, User"],
                ["File", "TargetFilename, SourceFilename"],
                ["Network", "DestinationIp, DestinationPort, DestinationIsPrivate, SourceIp"],
                ["TCC", "TCCService, TCCClient, TCCAllowed"],
            ])

            DocSubtitle("Compile & Load")
            DocCode("""
            # Save rule to Rules/<tactic>/my_rule.yml, then:
            make compile-rules    # compile YAML → JSON
            make restart          # restart daemon to load new rules

            # Or send SIGHUP to reload without restart:
            pkill -HUP maccrabd
            """)
        }
    }

    // MARK: - Actions

    private var actionsContent: some View {
        VStack(alignment: .leading, spacing: 16) {
            DocTitle("Response Actions")
            DocBody("""
            Response actions let MacCrab automatically react when a detection fires. \
            Configure them in an actions.json file.
            """)

            DocSubtitle("Available Actions")
            DocTable(headers: ["Action", "What It Does", "Risk Level"], rows: [
                ["log", "Write alert to database and JSONL (always happens)", "None"],
                ["notify", "Send macOS notification banner", "None"],
                ["kill", "SIGKILL the offending process", "High — may kill legitimate processes"],
                ["quarantine", "Move the triggering file to a vault directory", "High — may break applications"],
                ["script", "Run a custom shell script with alert context as env vars", "Variable"],
            ])

            DocSubtitle("Configuration File")
            DocBody("Create ~/Library/Application Support/MacCrab/actions.json:")
            DocCode("""
            {
              "defaults": [
                {"action": "notify", "minimumSeverity": "high"}
              ],
              "rules": {
                "rule-id-for-reverse-shell": [
                  {"action": "kill", "minimumSeverity": "critical"},
                  {"action": "notify", "minimumSeverity": "high"}
                ],
                "rule-id-for-malware-download": [
                  {"action": "quarantine", "minimumSeverity": "high"},
                  {
                    "action": "script",
                    "scriptPath": "/usr/local/bin/alert-to-slack.sh",
                    "minimumSeverity": "medium"
                  }
                ]
              }
            }
            """)

            DocSubtitle("Script Environment Variables")
            DocBody("Custom scripts receive alert context as environment variables:")
            DocCode("""
            MACCRAB_RULE_ID          # Rule identifier
            MACCRAB_RULE_TITLE       # Human-readable rule name
            MACCRAB_SEVERITY         # critical, high, medium, low
            MACCRAB_PROCESS_NAME     # Process that triggered the alert
            MACCRAB_PROCESS_PATH     # Full executable path
            MACCRAB_PROCESS_PID      # Process ID
            MACCRAB_PROCESS_CMDLINE  # Full command line
            MACCRAB_MITRE_TECHNIQUES # MITRE ATT&CK technique IDs
            MACCRAB_FILE_PATH        # File path (for file events)
            MACCRAB_DEST_IP          # Destination IP (for network events)
            MACCRAB_DEST_PORT        # Destination port (for network events)
            """)
        }
    }

    // MARK: - CLI

    private var cliContent: some View {
        VStack(alignment: .leading, spacing: 16) {
            DocTitle("CLI Reference")
            DocBody("maccrabctl is the command-line interface for managing MacCrab.")

            DocSubtitle("Monitoring")
            DocCode("""
            maccrabctl status                # daemon status + statistics
            maccrabctl events tail [N]       # last N events (default: 20)
            maccrabctl events search <query> # full-text search over events
            maccrabctl events stats          # event count statistics
            maccrabctl alerts [N]            # last N alerts (default: 20)
            maccrabctl watch                 # live stream alerts to terminal
            """)

            DocSubtitle("Rules")
            DocCode("""
            maccrabctl rules list            # list all loaded rules
            maccrabctl rules count           # count rules by category
            maccrabctl rule create [cat]     # generate YAML template
            """)

            DocSubtitle("Export & Response")
            DocCode("""
            maccrabctl export json [N]       # export alerts as JSON
            maccrabctl export csv [N]        # export alerts as CSV
            maccrabctl suppress <rule> <path> # allowlist process for a rule
            """)

            DocSubtitle("Make Targets")
            DocCode("""
            make dev           # build + restart daemon + open app
            make restart       # restart daemon (no rebuild)
            make stop          # stop daemon and app
            make status        # show daemon status
            make watch         # live alert stream
            make test          # run test suite
            make clear-data    # delete all events/alerts
            make install       # system-wide install (sudo)
            """)
        }
    }

    // MARK: - Tuning

    private var tuningContent: some View {
        VStack(alignment: .leading, spacing: 16) {
            DocTitle("Tuning & Allowlists")
            DocBody("""
            Real environments generate false positives. MacCrab provides several \
            ways to tune detection to your specific setup.
            """)

            DocSubtitle("Per-Rule Process Suppression")
            DocCode("""
            # Allowlist a process for a specific rule
            maccrabctl suppress <rule-id> /path/to/legitimate/binary

            # Stored in ~/Library/Application Support/MacCrab/suppressions.json
            # Restart daemon to apply: make restart
            """)

            DocSubtitle("Disable Noisy Rules")
            DocBody("""
            In the Rules tab, you can toggle individual rules on/off. Or edit the \
            compiled JSON and set "enabled": false.
            """)

            DocSubtitle("Alert Deduplication")
            DocBody("""
            The same rule + same process combination is automatically suppressed \
            for 1 hour after the first alert. This prevents alert storms from \
            repetitive activity.
            """)

            DocSubtitle("Baseline Learning")
            DocBody("""
            The baseline anomaly engine learns normal process relationships for 7 \
            days before alerting. During this period it records what parent processes \
            normally spawn what children. After learning, it alerts on novel \
            combinations.

            To reset and re-learn:
            """)
            DocCode("""
            # Reset baseline (re-enters 7-day learning mode)
            # Currently requires restarting the daemon with a fresh config
            make clear-data
            make restart
            """)

            DocSubtitle("Notification Threshold")
            DocBody("""
            By default, only high and critical alerts produce macOS notifications. \
            Adjust in Settings → Notifications → Minimum severity.
            """)
        }
    }
}

// MARK: - Doc Components

private struct DocTitle: View {
    let text: String
    init(_ text: String) { self.text = text }
    var body: some View {
        Text(text)
            .font(.title)
            .fontWeight(.bold)
            .padding(.bottom, 4)
    }
}

private struct DocSubtitle: View {
    let text: String
    init(_ text: String) { self.text = text }
    var body: some View {
        Text(text)
            .font(.title3)
            .fontWeight(.semibold)
            .padding(.top, 8)
    }
}

private struct DocBody: View {
    let text: String
    init(_ text: String) { self.text = text }
    var body: some View {
        Text(text)
            .font(.body)
            .foregroundColor(.secondary)
            .fixedSize(horizontal: false, vertical: true)
    }
}

private struct DocBullets: View {
    let items: [String]
    init(_ items: [String]) { self.items = items }
    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            ForEach(items, id: \.self) { item in
                HStack(alignment: .top, spacing: 8) {
                    Text("\u{2022}")
                        .fontWeight(.bold)
                        .foregroundColor(.accentColor)
                    Text(item)
                        .font(.body)
                        .foregroundColor(.secondary)
                }
            }
        }
        .padding(.leading, 8)
    }
}

private struct DocCode: View {
    let text: String
    init(_ text: String) { self.text = text }
    var body: some View {
        Text(text)
            .font(.system(.body, design: .monospaced))
            .padding(12)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Color(nsColor: .textBackgroundColor).opacity(0.5))
            .clipShape(RoundedRectangle(cornerRadius: 6))
            .textSelection(.enabled)
    }
}

private struct DocTable: View {
    let headers: [String]
    let rows: [[String]]

    var body: some View {
        VStack(spacing: 0) {
            // Header
            HStack(spacing: 0) {
                ForEach(headers.indices, id: \.self) { i in
                    Text(headers[i])
                        .font(.caption)
                        .fontWeight(.semibold)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(6)
                }
            }
            .background(Color.accentColor.opacity(0.1))

            Divider()

            // Rows
            ForEach(rows.indices, id: \.self) { rowIdx in
                HStack(spacing: 0) {
                    ForEach(rows[rowIdx].indices, id: \.self) { colIdx in
                        Text(rows[rowIdx][colIdx])
                            .font(.caption)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .padding(6)
                    }
                }
                .background(rowIdx % 2 == 0 ? Color.clear : Color.secondary.opacity(0.05))
            }
        }
        .clipShape(RoundedRectangle(cornerRadius: 6))
        .overlay(RoundedRectangle(cornerRadius: 6).stroke(Color.secondary.opacity(0.2)))
    }
}
