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

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                HStack {
                    Text("Integrations")
                        .font(.title2).fontWeight(.bold)
                    Spacer()
                    Button {
                        Task { await scanTools() }
                    } label: {
                        Label("Scan", systemImage: "arrow.triangle.2.circlepath")
                    }
                    .disabled(isScanning)
                }
                .padding(.horizontal)
                .padding(.top)

                Text("MacCrab detects and correlates alerts from other macOS security tools. Read-only — MacCrab never modifies other tools' configuration.")
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
                        Text("Click Scan to detect installed security tools")
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

                    Text("Available Integrations")
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
                            Text(name)
                                .font(.callout)
                                .foregroundColor(.secondary)
                            Spacer()
                            Text("Not installed")
                                .font(.caption)
                                .foregroundColor(.secondary)
                        }
                        .padding(.horizontal)
                        .padding(.vertical, 4)
                    }

                    // Export section
                    Divider().padding(.horizontal)

                    GroupBox("Export for Other Tools") {
                        VStack(alignment: .leading, spacing: 8) {
                            Text("Generate threat intel in formats compatible with other tools:")
                                .font(.caption).foregroundColor(.secondary)

                            HStack {
                                Button("Export .lsrules for Little Snitch") {
                                    exportLSRules()
                                }
                                .font(.caption)

                                Button("Export IOCs as CSV") {
                                    exportCSV()
                                }
                                .font(.caption)
                            }

                            Text("Exported files can be manually imported into each tool. MacCrab never modifies other tools' configuration.")
                                .font(.caption2).foregroundColor(.secondary)
                        }
                        .padding(4)
                    }
                    .padding(.horizontal)
                }

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
                            Text(tool.isRunning ? "Running" : "Installed")
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
    }
}
