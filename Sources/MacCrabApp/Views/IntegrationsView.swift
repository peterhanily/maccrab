// IntegrationsView.swift
// MacCrabApp
//
// Dashboard tab showing detected macOS security tools, their status,
// and export options for threat intel sharing.
// MacCrab is read-only — it never modifies other tools' configuration.

import SwiftUI
import AppKit
import UniformTypeIdentifiers
import MacCrabCore

struct IntegrationsView: View {
    @ObservedObject var appState: AppState
    @State private var installedTools: [SecurityToolIntegrations.InstalledTool] = []
    @State private var isScanning = false
    @Environment(\.accessibilityShowButtonShapes) var showButtonShapes

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                HStack {
                    Text(String(localized: "integrations.title", defaultValue: "Integrations"))
                        .font(.title2).fontWeight(.bold)
                    Spacer()
                    Button {
                        Task { await scanTools() }
                    } label: {
                        Label(String(localized: "integrations.scan", defaultValue: "Scan"), systemImage: "arrow.triangle.2.circlepath")
                    }
                    .disabled(isScanning)
                    .accessibilityLabel(String(localized: "integrations.scan", defaultValue: "Scan"))
                    .accessibilityHint(String(localized: "integrations.scanHint", defaultValue: "Scans for installed security tools"))
                    .keyboardShortcut("r", modifiers: .command)
                }
                .padding(.horizontal)
                .padding(.top)

                Text(String(localized: "integrations.description", defaultValue: "MacCrab detects and correlates alerts from other macOS security tools. Read-only \u{2014} MacCrab never modifies other tools' configuration."))
                    .font(.caption)
                    .foregroundColor(.secondary)
                    .padding(.horizontal)

                Divider()

                if installedTools.isEmpty && !isScanning {
                    VStack(spacing: 12) {
                        Spacer()
                        Image(systemName: "puzzlepiece.extension")
                            .font(.system(size: 48))
                            .foregroundColor(.secondary.opacity(0.5))
                            .accessibilityHidden(true)
                        Text(String(localized: "integrations.clickScan", defaultValue: "Click Scan to detect installed security tools"))
                            .font(.headline)
                            .foregroundColor(.secondary)
                        Spacer()
                    }
                    .frame(maxWidth: .infinity)
                } else {
                    // Installed tools
                    ForEach(installedTools, id: \.name) { tool in
                        ToolCard(tool: tool)
                    }
                    .padding(.horizontal)

                    // Tools not found
                    Divider().padding(.horizontal)

                    Text(String(localized: "integrations.available", defaultValue: "Available Integrations"))
                        .font(.headline)
                        .padding(.horizontal)

                    let installedNames = Set(installedTools.map(\.name))
                    let allTools = ["Little Snitch", "BlockBlock", "LuLu", "KnockKnock", "OverSight", "Santa", "CrowdStrike Falcon", "SentinelOne"]
                    let missing = allTools.filter { !installedNames.contains($0) }

                    ForEach(missing, id: \.self) { name in
                        HStack {
                            Image(systemName: "circle")
                                .foregroundColor(.secondary.opacity(0.3))
                                .font(.caption)
                                .accessibilityHidden(true)
                            Text(name)
                                .font(.callout)
                                .foregroundColor(.secondary)
                            Spacer()
                            Text(String(localized: "integrations.notInstalled", defaultValue: "Not installed"))
                                .font(.caption)
                                .foregroundColor(.secondary)
                        }
                        .padding(.horizontal)
                        .padding(.vertical, 4)
                    }

                    // Export section
                    Divider().padding(.horizontal)

                    GroupBox(String(localized: "integrations.export", defaultValue: "Export for Other Tools")) {
                        VStack(alignment: .leading, spacing: 8) {
                            Text(String(localized: "integrations.exportDesc", defaultValue: "Generate threat intel in formats compatible with other tools:"))
                                .font(.caption).foregroundColor(.secondary)

                            HStack {
                                Button(String(localized: "integrations.exportLSRules", defaultValue: "Export .lsrules for Little Snitch")) {
                                    exportLSRules()
                                }
                                .font(.caption)
                                .accessibilityLabel(String(localized: "integrations.exportLSRules", defaultValue: "Export .lsrules for Little Snitch"))
                                .accessibilityHint(String(localized: "integrations.exportLSRulesHint", defaultValue: "Saves threat intel in Little Snitch format"))
                                .keyboardShortcut("e", modifiers: .command)

                                Button(String(localized: "integrations.exportCSV", defaultValue: "Export IOCs as CSV")) {
                                    exportCSV()
                                }
                                .font(.caption)
                                .accessibilityLabel(String(localized: "integrations.exportCSV", defaultValue: "Export IOCs as CSV"))
                                .accessibilityHint(String(localized: "integrations.exportCSVHint", defaultValue: "Exports all indicators of compromise as a CSV file"))
                            }

                            Text(String(localized: "integrations.exportNote", defaultValue: "Exported files can be manually imported into each tool. MacCrab never modifies other tools' configuration."))
                                .font(.caption2).foregroundColor(.secondary)
                        }
                        .padding(4)
                    }
                    .padding(.horizontal)
                }

                // Fleet Telemetry
                Divider().padding(.horizontal)

                GroupBox(String(localized: "integrations.fleet", defaultValue: "Fleet Telemetry")) {
                    VStack(alignment: .leading, spacing: 8) {
                        HStack {
                            Circle()
                                .fill(appState.fleetStatus.isConfigured ? Color.green : Color.secondary)
                                .frame(width: 8, height: 8)
                            Text(appState.fleetStatus.isConfigured
                                ? String(localized: "integrations.fleetConnected", defaultValue: "Configured")
                                : String(localized: "integrations.fleetNotConfigured", defaultValue: "Not configured"))
                                .font(.callout)
                            Spacer()
                        }

                        if appState.fleetStatus.isConfigured {
                            Text(appState.fleetStatus.fleetURL)
                                .font(.caption)
                                .foregroundColor(.secondary)
                        }

                        Text(String(localized: "integrations.fleetHelp", defaultValue: "Fleet telemetry shares threat intel across multiple Macs. Set MACCRAB_FLEET_URL and optionally MACCRAB_FLEET_KEY before starting the detection engine."))
                            .font(.caption2)
                            .foregroundColor(.secondary)
                    }
                    .padding(4)
                }
                .padding(.horizontal)

                Spacer()
            }
        }
        .task { await scanTools() }
    }

    private func scanTools() async {
        isScanning = true
        let integrations = SecurityToolIntegrations()
        installedTools = await integrations.detectInstalledTools()
        isScanning = false
    }

    private func exportLSRules() {
        Task {
            let integrations = SecurityToolIntegrations()
            let lsrules = await integrations.generateLSRules(domains: [], ips: [])
            let panel = NSSavePanel()
            panel.allowedContentTypes = [.json]
            panel.nameFieldStringValue = "MacCrab-ThreatIntel.lsrules"
            if panel.runModal() == .OK, let url = panel.url {
                try? lsrules.write(to: url, atomically: true, encoding: .utf8)
            }
        }
    }

    private func exportCSV() {
        let panel = NSSavePanel()
        panel.allowedContentTypes = [.commaSeparatedText]
        panel.nameFieldStringValue = "MacCrab-IOCs.csv"
        if panel.runModal() == .OK, let url = panel.url {
            let csv = "type,value,source\n"  // Header only for now
            try? csv.write(to: url, atomically: true, encoding: .utf8)
        }
    }
}

// MARK: - Tool Card

struct ToolCard: View {
    let tool: SecurityToolIntegrations.InstalledTool

    var body: some View {
        GroupBox {
            HStack(alignment: .top, spacing: 12) {
                Image(systemName: tool.isRunning ? "checkmark.shield.fill" : "shield")
                    .font(.title2)
                    .foregroundColor(tool.isRunning ? .green : .secondary)
                    .frame(width: 32)
                    .accessibilityLabel(tool.isRunning ? "Running" : "Not running")

                VStack(alignment: .leading, spacing: 4) {
                    HStack {
                        Text(tool.name)
                            .font(.headline)
                        if let version = tool.version {
                            Text("v\(version)")
                                .font(.caption)
                                .foregroundColor(.secondary)
                        }
                        Spacer()
                        HStack(spacing: 4) {
                            Circle()
                                .fill(tool.isRunning ? Color.green : Color.secondary)
                                .frame(width: 6, height: 6)
                            Text(tool.isRunning
                                ? String(localized: "integrations.running", defaultValue: "Running")
                                : String(localized: "integrations.installed", defaultValue: "Installed"))
                                .font(.caption)
                                .foregroundColor(tool.isRunning ? .green : .secondary)
                        }
                    }

                    HStack(spacing: 6) {
                        ForEach(tool.capabilities, id: \.self) { cap in
                            Text(cap)
                                .font(.caption2)
                                .padding(.horizontal, 6)
                                .padding(.vertical, 2)
                                .background(Color.secondary.opacity(0.1))
                                .clipShape(Capsule())
                        }
                    }

                    if let logPath = tool.logPath {
                        Text("Log: \(logPath)")
                            .font(.caption2)
                            .foregroundColor(.secondary)
                    }
                }
            }
            .padding(4)
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(tool.name), \(tool.isRunning ? "running" : "installed")")
    }
}
