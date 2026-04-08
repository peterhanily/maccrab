// AIActivityView.swift
// MacCrabApp
//
// Dashboard tab showing AI coding tool sessions and their activity.

import SwiftUI
import MacCrabCore

struct AIActivityView: View {
    @ObservedObject var appState: AppState

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
                    // Status cards
                    HStack(spacing: 16) {
                        StatusCard(
                            title: "AI Guard",
                            value: "Active",
                            icon: "shield.checkered",
                            color: .green
                        )
                        StatusCard(
                            title: "Tools Monitored",
                            value: "8",
                            icon: "cpu",
                            color: .blue
                        )
                        StatusCard(
                            title: "Credential Fence",
                            value: "30+ paths",
                            icon: "lock.shield",
                            color: .orange
                        )
                        StatusCard(
                            title: "AI Alerts",
                            value: "\(appState.dashboardAlerts.filter { $0.ruleTitle.contains("AI") || $0.ruleTitle.contains("🦀") }.count)",
                            icon: "exclamationmark.triangle",
                            color: .red
                        )
                    }

                    // What's monitored
                    GroupBox {
                        VStack(alignment: .leading, spacing: 12) {
                            Text(String(localized: "aiGuard.whatMonitors", defaultValue: "What AI Guard Monitors"))
                                .font(.headline)

                            LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible())], spacing: 10) {
                                MonitorItem(icon: "terminal", title: "Shell Spawning", desc: "Every shell process spawned by AI tools")
                                MonitorItem(icon: "lock.open", title: "Credential Access", desc: "SSH keys, .env, AWS, tokens, keychains")
                                MonitorItem(icon: "folder.badge.questionmark", title: "Project Boundary", desc: "File writes outside project directory")
                                MonitorItem(icon: "shippingbox", title: "Package Installs", desc: "npm, pip, cargo, brew from AI context")
                                MonitorItem(icon: "arrow.up.arrow.down", title: "Privilege Escalation", desc: "sudo and setuid from AI processes")
                                MonitorItem(icon: "network", title: "Network Activity", desc: "Outbound connections from AI children")
                                MonitorItem(icon: "doc.text.magnifyingglass", title: "Prompt Injection", desc: "Forensicate.ai scanning of commands")
                                MonitorItem(icon: "clock.arrow.circlepath", title: "Persistence", desc: "LaunchAgents, cron, login items")
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
                                ToolBadge(name: "Codex", icon: "⚡")
                                ToolBadge(name: "OpenClaw", icon: "🦞")
                                ToolBadge(name: "Cursor", icon: "🖱️")
                                ToolBadge(name: "Aider", icon: "🔧")
                                ToolBadge(name: "Copilot", icon: "✈️")
                                ToolBadge(name: "Continue", icon: "▶️")
                                ToolBadge(name: "Windsurf", icon: "🏄")
                            }
                        }
                        .padding(8)
                    }

                    // Recent AI alerts
                    GroupBox {
                        VStack(alignment: .leading, spacing: 12) {
                            Text(String(localized: "aiGuard.recentAlerts", defaultValue: "Recent AI Safety Alerts"))
                                .font(.headline)

                            let aiAlerts = appState.dashboardAlerts.filter {
                                $0.ruleTitle.contains("AI") || $0.ruleTitle.contains("🦀") ||
                                $0.ruleTitle.contains("Credential") || $0.ruleTitle.contains("Boundary") ||
                                $0.ruleTitle.contains("Injection")
                            }

                            if aiAlerts.isEmpty {
                                HStack {
                                    Image(systemName: "checkmark.shield")
                                        .font(.title)
                                        .foregroundColor(.green)
                                        .accessibilityHidden(true)
                                    VStack(alignment: .leading) {
                                        Text(String(localized: "aiGuard.noAlerts", defaultValue: "No AI safety alerts"))
                                            .font(.headline)
                                        Text(String(localized: "aiGuard.noAlertsDesc", defaultValue: "AI tools are operating within safe boundaries"))
                                            .font(.caption)
                                            .foregroundColor(.secondary)
                                    }
                                }
                                .padding()
                            } else {
                                ForEach(aiAlerts.prefix(10)) { alert in
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
                                    }
                                }
                            }
                        }
                        .padding(8)
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
                                ForEach(CredentialFence.allPatterns.prefix(16), id: \.0) { pattern, type in
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
