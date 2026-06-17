// V2DocsWorkspace.swift
// Spec §7.7 — embedded reference and onboarding.

import SwiftUI

public struct V2DocsWorkspace: View {
    @ObservedObject var state: V2DashboardState
    @State private var selectedDoc: V2DocEntry = .gettingStarted

    public init(state: V2DashboardState) { self.state = state }

    public var body: some View {
        HStack(alignment: .top, spacing: 0) {
            docNav
            docArticle
        }
    }

    private var docNav: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Reference").font(V2Theme.cardTitle()).foregroundStyle(V2Theme.tertiaryText)
                .padding(.bottom, 4)
            ForEach(V2DocEntry.allCases, id: \.self) { entry in
                let isOn = selectedDoc == entry
                Button {
                    selectedDoc = entry
                } label: {
                    HStack(spacing: 8) {
                        Image(systemName: entry.icon)
                            .foregroundStyle(isOn ? V2Theme.primaryText : V2Theme.mutedText)
                            .scaledSystem(11, weight: .medium)
                            .frame(width: 18)
                        Text(entry.title)
                            .scaledSystem(12, weight: isOn ? .semibold : .medium)
                            .foregroundStyle(isOn ? V2Theme.primaryText : V2Theme.neutral)
                            .lineLimit(1)
                        Spacer()
                    }
                    .padding(.horizontal, 10).padding(.vertical, 7)
                    .background(isOn ? V2Theme.panelBackground : .clear)
                    .overlay(
                        Rectangle().fill(isOn ? V2Theme.brand : .clear).frame(width: 2),
                        alignment: .leading
                    )
                    .clipShape(RoundedRectangle(cornerRadius: V2Theme.smallCornerRadius))
                }
                .buttonStyle(.plain)
            }
            Spacer()
        }
        .padding(20)
        .frame(width: 240)
        .background(V2Theme.sidebarBackground.opacity(0.6))
        .overlay(
            Rectangle().fill(V2Theme.panelBorder).frame(width: 1),
            alignment: .trailing
        )
    }

    private var docArticle: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                HStack(spacing: 8) {
                    V2StatusChip(selectedDoc.kind, kind: .data)
                    Text(selectedDoc.title).font(V2Theme.workspaceTitle()).foregroundStyle(V2Theme.primaryText)
                }
                Text(selectedDoc.subtitle)
                    .font(V2Theme.body()).foregroundStyle(V2Theme.mutedText)

                ForEach(selectedDoc.sections, id: \.title) { sec in
                    VStack(alignment: .leading, spacing: 8) {
                        Text(sec.title).font(V2Theme.sectionTitle()).foregroundStyle(V2Theme.primaryText)
                        Text(sec.body).font(V2Theme.body()).foregroundStyle(V2Theme.neutral)
                            .fixedSize(horizontal: false, vertical: true)
                        if !sec.codeBlock.isEmpty {
                            Text(sec.codeBlock)
                                .font(V2Theme.mono())
                                .foregroundStyle(V2Theme.primaryText)
                                .padding(12)
                                .frame(maxWidth: .infinity, alignment: .leading)
                                .background(V2Theme.sidebarBackground.opacity(0.6))
                                .clipShape(RoundedRectangle(cornerRadius: V2Theme.smallCornerRadius))
                                .textSelection(.enabled)
                        }
                    }
                    .padding(.vertical, 4)
                }

                if !selectedDoc.related.isEmpty {
                    VStack(alignment: .leading, spacing: 8) {
                        Text("Related").font(V2Theme.sectionTitle()).foregroundStyle(V2Theme.primaryText)
                        HStack(spacing: 8) {
                            ForEach(selectedDoc.related, id: \.self) { rel in
                                if let entry = V2DocEntry.allCases.first(where: { $0.title == rel }) {
                                    Button { selectedDoc = entry } label: {
                                        HStack(spacing: 6) {
                                            Image(systemName: entry.icon).scaledSystem(11)
                                            Text(rel).font(V2Theme.body())
                                        }
                                        .foregroundStyle(V2Theme.dataAccent)
                                        .padding(.horizontal, 10).padding(.vertical, 6)
                                        .background(V2Theme.dataAccent.opacity(0.10))
                                        .overlay(
                                            RoundedRectangle(cornerRadius: V2Theme.smallCornerRadius)
                                                .stroke(V2Theme.dataAccent.opacity(0.3), lineWidth: 1)
                                        )
                                        .clipShape(RoundedRectangle(cornerRadius: V2Theme.smallCornerRadius))
                                    }
                                    .buttonStyle(.plain)
                                }
                            }
                        }
                    }
                }
            }
            .padding(16)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }
}

// MARK: - Doc entries

private enum V2DocEntry: CaseIterable, Hashable {
    case gettingStarted, traceGraph, traceBundle, aiGuard, mcp, rules, intel, settings, troubleshooting

    var title: String {
        switch self {
        case .gettingStarted:    return "Getting started"
        case .traceGraph:        return "TraceGraph"
        case .traceBundle:       return ".maccrabtrace bundles"
        case .aiGuard:           return "AI Guard"
        case .mcp:               return "MCP servers"
        case .rules:             return "Detection rules"
        case .intel:             return "Threat intel"
        case .settings:          return "Settings reference"
        case .troubleshooting:   return "Troubleshooting"
        }
    }
    var subtitle: String {
        switch self {
        case .gettingStarted:    return "What MacCrab does, how it stays local, and how to verify it's running."
        case .traceGraph:        return "The causal investigation engine that powers Investigation › TraceGraph."
        case .traceBundle:       return "Forensic flight recorder format — signed, replayable, exportable."
        case .aiGuard:           return "How MacCrab observes AI coding tools and MCP servers."
        case .mcp:               return "MacCrab's own MCP server lets agents query its data."
        case .rules:             return "Sigma-compatible YAML rules across 19 tactic directories."
        case .intel:             return "Pluggable threat-intel feeds with health monitoring."
        case .settings:          return "Daemon config keys + dashboard preferences."
        case .troubleshooting:   return "Common issues and what to check."
        }
    }
    var kind: String {
        switch self {
        case .gettingStarted, .troubleshooting: return "GUIDE"
        case .traceGraph, .traceBundle, .mcp:   return "ARCHITECTURE"
        case .aiGuard, .rules, .intel:          return "FEATURE"
        case .settings:                         return "REFERENCE"
        }
    }
    var icon: String {
        switch self {
        case .gettingStarted:    return "play.circle"
        case .traceGraph:        return "point.3.connected.trianglepath.dotted"
        case .traceBundle:       return "doc.zipper"
        case .aiGuard:           return "brain.head.profile"
        case .mcp:               return "server.rack"
        case .rules:             return "shield.lefthalf.filled"
        case .intel:             return "globe.americas.fill"
        case .settings:          return "gearshape.fill"
        case .troubleshooting:   return "wrench.and.screwdriver.fill"
        }
    }
    var sections: [DocSection] {
        switch self {
        case .gettingStarted:
            return [
                DocSection(title: "Local-first design",
                           body: "MacCrab runs entirely on this Mac. Detection rules execute locally, alerts are stored in a local SQLite DB, and the AI features default to a local Ollama backend. Cloud LLMs are opt-in and pre-redact identifiers.",
                           codeBlock: ""),
                DocSection(title: "Verify it's running",
                           body: "From the menubar: the sidebar footer reads \"Protection active\" when the daemon is healthy, \"Protection degraded\" if heartbeats are stale or score is low, \"Protection inactive\" if no daemon is detected. From CLI:",
                           codeBlock: "$ maccrabctl status   # daemon, rules, DB size, mode"),
            ]
        case .traceGraph:
            return [
                DocSection(title: "What it is",
                           body: "TraceGraph is a rolling causal graph over recent process / file / network / TCC activity. Each node is an entity (process, file, peer); each edge is a causal relation (spawn, write, connect, grant).",
                           codeBlock: ""),
                DocSection(title: "Anchor verdict",
                           body: "Each trace has a single anchor — the entity considered most load-bearing for the verdict. Investigations and defense recommendations always target the anchor's identity, not just its PID.",
                           codeBlock: ""),
                DocSection(title: "Storage",
                           body: "Materialized traces live in a separate SQLite store (tracegraph.db) so the events.db hot path never blocks on graph queries.",
                           codeBlock: ""),
            ]
        case .traceBundle:
            return [
                DocSection(title: "What's in it",
                           body: "A .maccrabtrace bundle is a signed zip containing the trace's nodes, edges, raw events, anchor verdict, and a Merkle root over the canonical artifact ordering. The bundle is replayable — feeding it back into a fresh MacCrab reproduces the same verdict.",
                           codeBlock: ""),
                DocSection(title: "Verify a bundle",
                           body: "Use maccrabctl:",
                           codeBlock: "$ maccrabctl trace verify trace.maccrabtrace\n✓ Schema valid\n✓ Merkle root matches\n✓ Signature verified (SE key)\n✓ Replay reproduces verdict"),
            ]
        case .aiGuard:
            return [
                DocSection(title: "What it watches",
                           body: "AI coding tools (Claude Code, Codex, Cursor, Continue.dev, Aider, …) and the MCP servers they reach. MacCrab attributes each file write / network connect / process spawn to the originating agent session.",
                           codeBlock: ""),
                DocSection(title: "Common alerts",
                           body: "Most AI Guard alerts fire on: writing credentials-shaped files outside known scope, sudden MCP tool inflation, agents spawning unsigned binaries, or agents hitting honeyfile paths.",
                           codeBlock: ""),
            ]
        case .mcp:
            return [
                DocSection(title: "MacCrab as an MCP server",
                           body: "The bundled maccrab-mcp binary exposes 17 tools so AI agents can query MacCrab data with structured tool calls. Triage tools: get_alerts, get_alert_detail, cluster_alerts, get_events, get_campaigns, suppress_alert, suppress_campaign, get_ai_alerts. Investigation tools: hunt, get_traces, get_trace_detail, hunt_trace, trace_from_event, verify_bundle. Status: get_status, get_security_score, scan_text. All MCP responses are sanitized before reaching the agent.",
                           codeBlock: "{\n  \"mcpServers\": {\n    \"maccrab\": {\n      \"command\": \"/usr/local/bin/maccrab-mcp\"\n    }\n  }\n}"),
            ]
        case .rules:
            return [
                DocSection(title: "Authoring rules",
                           body: "Drop YAML files in Rules/<tactic>/, run make compile-rules, then send SIGHUP to the daemon to hot-reload.",
                           codeBlock: "# Rules/persistence/launchd_shell_spawn.yml\ntitle: LaunchAgent invokes shell directly\nlevel: high\ndetection:\n  selection:\n    ProcessName|contains: launchd\n    CommandLine|contains: ['/bin/sh -c', '/bin/bash -c']\n  condition: selection"),
            ]
        case .intel:
            return [
                DocSection(title: "Adding a feed",
                           body: "Each feed is a JSON file under intel/feeds/ describing source URL, parser, and refresh cadence. The collector then tracks fetch health.",
                           codeBlock: ""),
            ]
        case .settings:
            return [
                DocSection(title: "daemon_config.json",
                           body: "All keys are optional. Missing keys use defaults from DaemonConfig.swift. Common keys:",
                           codeBlock: "{\n  \"behavior_alert_threshold\": 10.0,\n  \"behavior_critical_threshold\": 20.0,\n  \"statistical_z_threshold\": 3.0,\n  \"max_database_size_mb\": 500,\n  \"retention_days\": 30\n}"),
            ]
        case .troubleshooting:
            return [
                DocSection(title: "Empty TraceGraph",
                           body: "If the dashboard reports zero traces but the daemon is running, the materializer hasn't yet observed an anchor candidate. Traces appear once the daemon correlates a multi-step chain of activity — give it time on an active machine.",
                           codeBlock: ""),
                DocSection(title: "ES entitlement missing",
                           body: "If System › Health shows EndpointSecurity as down, the system extension wasn't activated. Open MacCrab.app and click \"Activate protection\" in the onboarding banner.",
                           codeBlock: ""),
            ]
        }
    }
    var related: [String] {
        switch self {
        case .gettingStarted:    return ["TraceGraph", "Detection rules", "Settings reference"]
        case .traceGraph:        return [".maccrabtrace bundles", "AI Guard"]
        case .traceBundle:       return ["TraceGraph", "Troubleshooting"]
        case .aiGuard:           return ["MCP servers", "Detection rules"]
        case .mcp:               return ["AI Guard"]
        case .rules:             return ["AI Guard", "Settings reference"]
        case .intel:             return []
        case .settings:          return ["Detection rules", "Troubleshooting"]
        case .troubleshooting:   return ["Getting started", "Settings reference"]
        }
    }
}

private struct DocSection { let title: String; let body: String; let codeBlock: String }
