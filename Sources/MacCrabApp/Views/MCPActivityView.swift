// MCPActivityView.swift
// MacCrabApp
//
// MCP Server Activity panel (v1.7.0). Renders the per-(tool, server)
// behavioral baselines that `MCPBaselineService` learns during runtime
// and the recent baseline-anomaly alerts that flowed through the alert
// pipeline. Reads `<dataDir>/mcp_baselines.json` written by the daemon
// every 30 s on the heartbeat tick.

import SwiftUI
import MacCrabCore

struct MCPActivityView: View {
    @ObservedObject var appState: AppState

    @State private var searchText: String = ""
    @State private var selectedBaseline: MCPServerBaseline?

    private var filtered: [MCPServerBaseline] {
        guard !searchText.isEmpty else { return appState.mcpBaselines }
        let q = searchText.lowercased()
        return appState.mcpBaselines.filter {
            $0.serverName.lowercased().contains(q) || $0.tool.lowercased().contains(q)
        }
    }

    private var recentAnomalies: [AlertViewModel] {
        appState.dashboardAlerts.filter {
            $0.ruleId.hasPrefix("maccrab.mcp.baseline-anomaly.")
            && !$0.suppressed
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header

            if filtered.isEmpty {
                emptyState
            } else {
                HSplitView {
                    serverList
                    detailPane
                }
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    // MARK: Header

    private var header: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text(String(localized: "mcp.title", defaultValue: "MCP Server Activity"))
                    .font(.title2).fontWeight(.bold)
                Spacer()
                if let last = appState.mcpBaselinesLastRefresh {
                    Text(String(localized: "mcp.lastUpdate", defaultValue: "Updated \(last.formatted(.relative(presentation: .named)))"))
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            Text(String(localized: "mcp.subtitle", defaultValue: "Per-MCP-server runtime fingerprints. Each row is one configured server under one AI tool. After 20 observations the server's baseline is promoted to enforcing — anything outside the fingerprint produces a Baseline Drift alert."))
                .font(.callout)
                .foregroundStyle(.secondary)

            HStack {
                Image(systemName: "magnifyingglass")
                    .foregroundStyle(.secondary)
                TextField(String(localized: "mcp.searchPlaceholder", defaultValue: "Search by server or tool name…"), text: $searchText)
                    .textFieldStyle(.roundedBorder)
            }

            if !recentAnomalies.isEmpty {
                anomaliesBanner
            }
        }
        .padding()
    }

    private var anomaliesBanner: some View {
        HStack(alignment: .top, spacing: 8) {
            Image(systemName: "exclamationmark.triangle.fill")
                .foregroundStyle(.orange)
            VStack(alignment: .leading, spacing: 2) {
                Text(String(localized: "mcp.anomaliesTitle", defaultValue: "\(recentAnomalies.count) recent baseline drift alert(s)"))
                    .fontWeight(.semibold)
                ForEach(recentAnomalies.prefix(3), id: \.id) { alert in
                    Text(alert.ruleTitle)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                }
                if recentAnomalies.count > 3 {
                    Text(String(localized: "mcp.anomaliesMore", defaultValue: "+ \(recentAnomalies.count - 3) more — see Alerts panel for full list"))
                        .font(.caption)
                        .foregroundStyle(.tertiary)
                }
            }
            Spacer()
        }
        .padding(8)
        .background(Color.orange.opacity(0.1))
        .clipShape(RoundedRectangle(cornerRadius: 6))
    }

    // MARK: Server list (left pane)

    private var serverList: some View {
        List(filtered, id: \.serverKey, selection: $selectedBaseline) { baseline in
            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    HStack(spacing: 6) {
                        Text(baseline.serverName)
                            .fontWeight(.semibold)
                        stateBadge(baseline.state)
                    }
                    Text("\(baseline.tool) · \(baseline.observationCount) obs")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Spacer()
            }
            .tag(baseline)
        }
        .frame(minWidth: 260, idealWidth: 320, maxWidth: 400)
    }

    private func stateBadge(_ state: MCPServerBaseline.BaselineState) -> some View {
        let label: String = state == .learning
            ? String(localized: "mcp.state.learning", defaultValue: "learning")
            : String(localized: "mcp.state.enforcing", defaultValue: "enforcing")
        let color: Color = state == .learning ? .blue : .green
        return Text(label.uppercased())
            .font(.caption2.weight(.bold))
            .padding(.horizontal, 5)
            .padding(.vertical, 2)
            .background(color.opacity(0.15))
            .foregroundStyle(color)
            .clipShape(RoundedRectangle(cornerRadius: 3))
    }

    // MARK: Detail pane (right)

    private var detailPane: some View {
        Group {
            if let baseline = selectedBaseline {
                ScrollView {
                    VStack(alignment: .leading, spacing: 12) {
                        baselineHeader(baseline)

                        fingerprintGroup(
                            title: String(localized: "mcp.detail.fileBasenames", defaultValue: "File basenames"),
                            systemImage: "doc",
                            values: Array(baseline.fileBasenames).sorted()
                        )
                        fingerprintGroup(
                            title: String(localized: "mcp.detail.domains", defaultValue: "Network domains"),
                            systemImage: "globe",
                            values: Array(baseline.domains).sorted()
                        )
                        fingerprintGroup(
                            title: String(localized: "mcp.detail.children", defaultValue: "Child processes"),
                            systemImage: "tree",
                            values: Array(baseline.childBasenames).sorted()
                        )
                    }
                    .padding()
                }
            } else {
                VStack {
                    Spacer()
                    Text(String(localized: "mcp.detail.empty", defaultValue: "Select a server to inspect its baseline."))
                        .foregroundStyle(.secondary)
                    Spacer()
                }
                .frame(maxWidth: .infinity)
            }
        }
    }

    private func baselineHeader(_ b: MCPServerBaseline) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(b.serverName)
                .font(.title3).fontWeight(.semibold)
            Text("\(b.tool) · \(b.serverKey)")
                .font(.caption)
                .foregroundStyle(.secondary)
            HStack(spacing: 16) {
                Label("\(b.observationCount) " + String(localized: "mcp.detail.observations", defaultValue: "observations"),
                      systemImage: "wave.3.right")
                Label(String(localized: "mcp.detail.firstSeen", defaultValue: "First seen ") + b.firstSeen.formatted(.relative(presentation: .named)),
                      systemImage: "clock")
                Label(String(localized: "mcp.detail.lastSeen", defaultValue: "Last seen ") + b.lastSeen.formatted(.relative(presentation: .named)),
                      systemImage: "clock.arrow.circlepath")
            }
            .font(.caption)
            .foregroundStyle(.secondary)
        }
    }

    private func fingerprintGroup(title: String, systemImage: String, values: [String]) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Label("\(title) · \(values.count)", systemImage: systemImage)
                .font(.headline)
            if values.isEmpty {
                Text(String(localized: "mcp.detail.none", defaultValue: "(none observed yet)"))
                    .font(.caption)
                    .foregroundStyle(.secondary)
            } else {
                LazyVGrid(columns: [GridItem(.adaptive(minimum: 120))], alignment: .leading, spacing: 4) {
                    ForEach(values, id: \.self) { v in
                        Text(v)
                            .font(.system(.caption, design: .monospaced))
                            .padding(.horizontal, 5)
                            .padding(.vertical, 2)
                            .background(Color.secondary.opacity(0.1))
                            .clipShape(RoundedRectangle(cornerRadius: 3))
                    }
                }
            }
        }
    }

    // MARK: Empty state

    private var emptyState: some View {
        VStack(spacing: 12) {
            Spacer()
            Image(systemName: "puzzlepiece.extension")
                .font(.system(size: 48))
                .foregroundStyle(.tertiary)
            Text(String(localized: "mcp.empty.title", defaultValue: "No MCP baselines yet"))
                .font(.title3)
            Text(String(localized: "mcp.empty.body", defaultValue: "Baselines appear here once an AI coding tool (Claude Code, Cursor, Continue.dev, VS Code, Windsurf) launches a configured MCP server and the server takes any action MacCrab can observe (file access, network connect, child process spawn). The first 20 observations build the fingerprint; afterwards anything outside the fingerprint produces a Baseline Drift alert."))
                .font(.callout)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .frame(maxWidth: 480)
            Spacer()
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .padding()
    }
}
