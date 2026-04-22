// AIActivityView.swift
// MacCrabApp
//
// Dashboard tab showing AI coding tool sessions and their activity.

import SwiftUI
import MacCrabCore

struct AIActivityView: View {
    @ObservedObject var appState: AppState

    // MARK: - Derived alert sets

    /// All AI-related alerts: uses both ruleId patterns and display-title keywords.
    private var aiAlerts: [AlertViewModel] {
        let ruleIdKeywords = ["ai_tool", "ai-tool", "ai_guard", "credential_fence",
                              "boundary_violation", "mcp_server", "prompt_injection"]
        let titleKeywords  = ["AI", "Credential Fence", "Boundary", "Injection",
                              "MCP", "Prompt", "Jailbreak"]
        return appState.dashboardAlerts.filter { alert in
            let id    = alert.ruleId.lowercased()
            let title = alert.ruleTitle
            return ruleIdKeywords.contains(where: { id.contains($0) })
                || titleKeywords.contains(where: { title.contains($0) })
        }
    }

    private var credentialAlerts: [AlertViewModel] {
        aiAlerts.filter { $0.ruleId.contains("credential") || $0.ruleTitle.contains("Credential") }
    }

    private var boundaryAlerts: [AlertViewModel] {
        aiAlerts.filter { $0.ruleId.contains("boundary") || $0.ruleTitle.contains("Boundary") }
    }

    private var injectionAlerts: [AlertViewModel] {
        aiAlerts.filter {
            $0.ruleId.contains("injection") || $0.ruleId.contains("jailbreak")
            || $0.ruleTitle.contains("Injection") || $0.ruleTitle.contains("Jailbreak")
        }
    }

    /// Active (non-suppressed) AI alerts only.
    private var activeAIAlerts: [AlertViewModel] { aiAlerts.filter { !$0.suppressed } }

    /// Per-tool alert counts (keyed by process display name).
    private var alertsByTool: [(tool: String, alerts: [AlertViewModel])] {
        let grouped = Dictionary(grouping: activeAIAlerts) { alert -> String in
            let name = alert.processName
            // Map known AI tool process names to friendly labels.
            if name.contains("claude") || name.contains("Claude") { return "Claude Code" }
            if name.contains("cursor") || name.contains("Cursor") { return "Cursor" }
            if name.contains("codex")  || name.contains("Codex")  { return "Codex" }
            if name.contains("aider")  || name.contains("Aider")  { return "Aider" }
            if name.contains("copilot") { return "GitHub Copilot" }
            if name.contains("windsurf") { return "Windsurf" }
            if name.contains("continue") { return "Continue" }
            if name.contains("openclaw") || name.contains("OpenClaw") { return "OpenClaw" }
            return name.isEmpty ? "Unknown" : name
        }
        return grouped.map { (tool: $0.key, alerts: $0.value) }
            .sorted { $0.alerts.count > $1.alerts.count }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            // Header
            HStack(spacing: 12) {
                Text("🦀")
                    .font(.title2)
                Text(String(localized: "aiGuard.title", defaultValue: "AI Tool Activity"))
                    .font(.title2)
                    .fontWeight(.bold)

                Spacer()

                Text(String(localized: "aiGuard.subtitle", defaultValue: "Monitors Claude Code, Codex, OpenClaw, Cursor and their child processes"))
                    .font(.caption)
                    .foregroundColor(.secondary)
            }
            .padding()

            Divider()

            ScrollView {
                VStack(alignment: .leading, spacing: 20) {
                    // Status cards — all live counts
                    HStack(spacing: 16) {
                        StatusCard(
                            title: "AI Guard",
                            value: "Active",
                            icon: "shield.checkered",
                            color: .green
                        )
                        StatusCard(
                            title: "AI Alerts",
                            value: "\(activeAIAlerts.count)",
                            icon: "exclamationmark.triangle",
                            color: activeAIAlerts.isEmpty ? .green : .red
                        )
                        StatusCard(
                            title: "Cred Fence",
                            value: credentialAlerts.isEmpty ? "Clean" : "\(credentialAlerts.count) hit\(credentialAlerts.count == 1 ? "" : "s")",
                            icon: "lock.shield",
                            color: credentialAlerts.isEmpty ? .green : .orange
                        )
                        StatusCard(
                            title: "Injections",
                            value: injectionAlerts.isEmpty ? "None" : "\(injectionAlerts.count)",
                            icon: "doc.text.magnifyingglass",
                            color: injectionAlerts.isEmpty ? .green : .red
                        )
                        StatusCard(
                            title: "Boundary",
                            value: boundaryAlerts.isEmpty ? "Clean" : "\(boundaryAlerts.count)",
                            icon: "folder.badge.questionmark",
                            color: boundaryAlerts.isEmpty ? .green : .orange
                        )
                    }

                    // Activity by AI tool — shows which tool generated alerts
                    if !alertsByTool.isEmpty {
                        GroupBox {
                            VStack(alignment: .leading, spacing: 12) {
                                Text("Activity by AI Tool")
                                    .font(.headline)

                                ForEach(alertsByTool, id: \.tool) { entry in
                                    HStack(spacing: 10) {
                                        Circle()
                                            .fill(entry.alerts.contains { $0.severity == .critical } ? Color.red
                                                  : entry.alerts.contains { $0.severity == .high } ? Color.orange
                                                  : Color.yellow)
                                            .frame(width: 8, height: 8)
                                            .accessibilityHidden(true)

                                        Text(entry.tool)
                                            .font(.subheadline)
                                            .fontWeight(.medium)

                                        Spacer()

                                        // Mini breakdown
                                        let cred = entry.alerts.filter { $0.ruleTitle.contains("Credential") }.count
                                        let inj  = entry.alerts.filter { $0.ruleTitle.contains("Injection") }.count
                                        let bnd  = entry.alerts.filter { $0.ruleTitle.contains("Boundary") }.count
                                        let other = entry.alerts.count - cred - inj - bnd

                                        HStack(spacing: 6) {
                                            if cred  > 0 { TagChip(label: "\(cred) cred",  color: .orange) }
                                            if inj   > 0 { TagChip(label: "\(inj) inject", color: .red) }
                                            if bnd   > 0 { TagChip(label: "\(bnd) bound",  color: .yellow) }
                                            if other > 0 { TagChip(label: "\(other) other", color: .secondary) }
                                        }
                                    }
                                    .padding(.vertical, 4)
                                }
                            }
                            .padding(8)
                        }
                    }

                    // What's monitored
                    GroupBox {
                        VStack(alignment: .leading, spacing: 12) {
                            Text(String(localized: "aiGuard.whatMonitors", defaultValue: "What AI Guard Monitors"))
                                .font(.headline)

                            LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible())], spacing: 10) {
                                MonitorItem(icon: "terminal",                  title: "Shell Spawning",       desc: "Every shell process spawned by AI tools")
                                MonitorItem(icon: "lock.open",                 title: "Credential Access",    desc: "SSH keys, .env, AWS, tokens, keychains")
                                MonitorItem(icon: "folder.badge.questionmark", title: "Project Boundary",     desc: "File writes outside project directory")
                                MonitorItem(icon: "shippingbox",               title: "Package Installs",     desc: "npm, pip, cargo, brew from AI context")
                                MonitorItem(icon: "arrow.up.arrow.down",       title: "Privilege Escalation", desc: "sudo and setuid from AI processes")
                                MonitorItem(icon: "network",                   title: "Network Activity",     desc: "Outbound connections from AI children")
                                MonitorItem(icon: "doc.text.magnifyingglass",  title: "Prompt Injection",     desc: "Forensicate.ai scanning of commands")
                                MonitorItem(icon: "clock.arrow.circlepath",    title: "Persistence",          desc: "LaunchAgents, cron, login items")
                            }
                        }
                        .padding(8)
                    }

                    // Supported tools
                    GroupBox {
                        VStack(alignment: .leading, spacing: 12) {
                            Text(String(localized: "aiGuard.supportedTools", defaultValue: "Supported AI Coding Tools"))
                                .font(.headline)

                            LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible()), GridItem(.flexible()), GridItem(.flexible())], spacing: 10) {
                                ToolBadge(name: "Claude Code", icon: "🤖")
                                ToolBadge(name: "Codex",       icon: "⚡")
                                ToolBadge(name: "OpenClaw",    icon: "🦞")
                                ToolBadge(name: "Cursor",      icon: "🖱️")
                                ToolBadge(name: "Aider",       icon: "🔧")
                                ToolBadge(name: "Copilot",     icon: "✈️")
                                ToolBadge(name: "Continue",    icon: "▶️")
                                ToolBadge(name: "Windsurf",    icon: "🏄")
                            }
                        }
                        .padding(8)
                    }

                    // MCP self-protection tip — shown when there are no alerts
                    if activeAIAlerts.isEmpty {
                        GroupBox {
                            HStack(spacing: 12) {
                                Image(systemName: "checkmark.shield.fill")
                                    .font(.title2)
                                    .foregroundColor(.green)
                                    .accessibilityHidden(true)
                                VStack(alignment: .leading, spacing: 4) {
                                    Text(String(localized: "aiGuard.noAlerts", defaultValue: "No AI safety alerts"))
                                        .font(.headline)
                                    Text("AI tools are operating within safe boundaries. Use the `scan_text` MCP tool to check untrusted input before processing it.")
                                        .font(.caption)
                                        .foregroundColor(.secondary)
                                }
                            }
                            .padding(8)
                        }
                    }

                    // Recent AI alerts
                    if !activeAIAlerts.isEmpty {
                        GroupBox {
                            VStack(alignment: .leading, spacing: 12) {
                                Text(String(localized: "aiGuard.recentAlerts", defaultValue: "Recent AI Safety Alerts"))
                                    .font(.headline)

                                ForEach(activeAIAlerts.prefix(10)) { alert in
                                    HStack {
                                        Circle()
                                            .fill(alert.severityColor)
                                            .frame(width: 8, height: 8)
                                            .accessibilityHidden(true)
                                        VStack(alignment: .leading, spacing: 2) {
                                            Text(alert.ruleTitle)
                                                .font(.subheadline)
                                                .fontWeight(.medium)
                                            Text("\(alert.processName) — \(alert.dateTimeString)")
                                                .font(.caption)
                                                .foregroundColor(.secondary)
                                        }
                                        Spacer()
                                        Text(alert.severity.label)
                                            .font(.caption2)
                                            .foregroundColor(alert.severityColor)
                                            .padding(.horizontal, 6)
                                            .padding(.vertical, 2)
                                            .background(alert.severityColor.opacity(0.1))
                                            .clipShape(Capsule())
                                    }
                                }
                            }
                            .padding(8)
                        }
                    }

                    // Credential fence info
                    GroupBox {
                        VStack(alignment: .leading, spacing: 8) {
                            Text(String(localized: "aiGuard.credentialFenceTitle", defaultValue: "Credential Fence — Protected Paths"))
                                .font(.headline)
                            Text(String(localized: "aiGuard.credentialFenceDesc", defaultValue: "AI tools will trigger CRITICAL alerts if they access any of these:"))
                                .font(.caption)
                                .foregroundColor(.secondary)

                            LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible())], spacing: 4) {
                                ForEach(CredentialFence.allPatterns.prefix(16), id: \.0) { pattern, _ in
                                    HStack(spacing: 4) {
                                        Image(systemName: "lock.fill")
                                            .font(.caption2)
                                            .foregroundColor(.orange)
                                            .accessibilityHidden(true)
                                        Text(pattern)
                                            .font(.system(.caption2, design: .monospaced))
                                        Spacer()
                                    }
                                }
                            }
                        }
                        .padding(8)
                    }
                }
                .padding()
            }
        }
    }
}

// MARK: - Components

private struct StatusCard: View {
    let title: String
    let value: String
    let icon: String
    let color: Color

    var body: some View {
        VStack(spacing: 8) {
            Image(systemName: icon)
                .font(.title2)
                .foregroundColor(color)
                .accessibilityHidden(true)
            Text(value)
                .font(.title3)
                .fontWeight(.bold)
            Text(title)
                .font(.caption)
                .foregroundColor(.secondary)
        }
        .frame(maxWidth: .infinity)
        .padding()
        .background(color.opacity(0.08))
        .clipShape(RoundedRectangle(cornerRadius: 10))
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(title): \(value)")
    }
}

private struct TagChip: View {
    let label: String
    let color: Color

    var body: some View {
        Text(label)
            .font(.caption2)
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .background(color.opacity(0.15))
            .foregroundColor(color)
            .clipShape(Capsule())
    }
}

private struct MonitorItem: View {
    let icon: String
    let title: String
    let desc: String

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: icon)
                .font(.title3)
                .foregroundColor(.accentColor)
                .frame(width: 24)
            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                    .font(.subheadline)
                    .fontWeight(.medium)
                Text(desc)
                    .font(.caption)
                    .foregroundColor(.secondary)
            }
            Spacer()
        }
        .padding(8)
        .background(Color.secondary.opacity(0.05))
        .clipShape(RoundedRectangle(cornerRadius: 6))
    }
}

private struct ToolBadge: View {
    let name: String
    let icon: String

    var body: some View {
        HStack(spacing: 6) {
            Text(icon)
            Text(name)
                .font(.caption)
                .fontWeight(.medium)
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 6)
        .background(Color.accentColor.opacity(0.1))
        .clipShape(Capsule())
    }
}
