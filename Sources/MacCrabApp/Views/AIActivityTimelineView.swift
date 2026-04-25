// AIActivityTimelineView.swift
// MacCrabApp
//
// Renders the per-AI-tool agent-activity timeline produced by
// `AgentLineageService` in the daemon. The view reads
// `appState.aiSessions` (refreshed every poll cycle from the daemon's
// JSON snapshot at `<supportDir>/agent_lineage.json`) and lays each
// session out as a vertical chronology of LLM calls, process spawns,
// file reads/writes, network connections, and rule fires.
//
// This is the headline visibility win for v1.6.15. The wiki's
// positioning line "Lakera classifies your prompts — MacCrab sees what
// your agents actually did" was unsubstantiated until this view shipped:
// the daemon was already capturing the events but no UI rendered them.

import SwiftUI
import MacCrabCore

struct AIActivityTimelineView: View {
    @ObservedObject var appState: AppState
    /// Currently expanded session (the one whose events are rendered).
    /// Defaults to the most recently active session on first appearance.
    @State private var selectedPid: Int32?

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            header

            if appState.aiSessions.isEmpty {
                emptyState
            } else {
                sessionPicker

                let chosen = selectedSession
                if let session = chosen {
                    SessionTimelineCard(session: session)
                }
            }
        }
    }

    // MARK: - Subviews

    private var header: some View {
        HStack(alignment: .firstTextBaseline) {
            Text("Agent Activity Timeline")
                .font(.headline)
            Spacer()
            if let last = appState.aiSessionsLastRefresh {
                Text("Updated \(last.formatted(.relative(presentation: .named)))")
                    .font(.caption2)
                    .foregroundColor(.secondary)
            }
        }
    }

    private var emptyState: some View {
        VStack(spacing: 6) {
            Image(systemName: "waveform.path.ecg")
                .font(.title2)
                .foregroundColor(.secondary)
                .accessibilityHidden(true)
            Text("No active AI tool sessions")
                .font(.subheadline)
                .foregroundColor(.secondary)
            Text("Run Claude Code, Cursor, Codex, OpenClaw, Aider, Continue, or Windsurf and the timeline will populate within 30 seconds.")
                .font(.caption2)
                .foregroundColor(.secondary)
                .multilineTextAlignment(.center)
                .frame(maxWidth: 420)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 20)
    }

    private var sessionPicker: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 6) {
                ForEach(appState.aiSessions, id: \.aiPid) { session in
                    Button {
                        selectedPid = session.aiPid
                    } label: {
                        SessionChip(
                            session: session,
                            selected: session.aiPid == effectiveSelectedPid
                        )
                    }
                    .buttonStyle(.plain)
                }
            }
        }
    }

    private var effectiveSelectedPid: Int32? {
        if let chosen = selectedPid,
           appState.aiSessions.contains(where: { $0.aiPid == chosen }) {
            return chosen
        }
        return appState.aiSessions.first?.aiPid
    }

    private var selectedSession: AgentSessionSnapshot? {
        guard let pid = effectiveSelectedPid else { return nil }
        return appState.aiSessions.first(where: { $0.aiPid == pid })
    }
}

// MARK: - Session chip

private struct SessionChip: View {
    let session: AgentSessionSnapshot
    let selected: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            HStack(spacing: 4) {
                Text(toolLabel)
                    .font(.caption)
                    .fontWeight(.semibold)
                Text("pid \(session.aiPid)")
                    .font(.caption2)
                    .foregroundColor(.secondary)
            }
            HStack(spacing: 6) {
                Text("\(session.eventCount) ev")
                    .font(.caption2)
                    .foregroundColor(.secondary)
                if session.kindCounts.alerts > 0 {
                    Text("\(session.kindCounts.alerts)⚠︎")
                        .font(.caption2)
                        .foregroundColor(.orange)
                }
            }
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 6)
        .background(
            RoundedRectangle(cornerRadius: 6)
                .fill(selected ? Color.accentColor.opacity(0.15) : Color.secondary.opacity(0.08))
        )
        .overlay(
            RoundedRectangle(cornerRadius: 6)
                .stroke(selected ? Color.accentColor : Color.clear, lineWidth: 1)
        )
    }

    private var toolLabel: String {
        // Use the registry-canonical display name so we never drift from
        // the AIToolType enum when a new tool is added (the build break
        // catches that case for us).
        session.toolType.displayName
    }
}

// MARK: - Session timeline card

private struct SessionTimelineCard: View {
    let session: AgentSessionSnapshot

    /// At most this many events are rendered inline. Older events are
    /// elided behind a "Show all" disclosure to keep the UI snappy
    /// when a long-running session has thousands of events. The cap
    /// matches a roughly-screen-fitting list — analysts pivot via
    /// AlertDetailView for serious investigations.
    private static let inlineLimit = 80
    @State private var showAll = false

    private var eventsNewestFirst: [AgentEvent] {
        // The snapshot returns oldest-first; flip so the most recent
        // activity is at the top of the timeline (matching the way
        // existing AlertDashboard sorts).
        Array(session.events.reversed())
    }

    private var displayed: [AgentEvent] {
        showAll
            ? eventsNewestFirst
            : Array(eventsNewestFirst.prefix(Self.inlineLimit))
    }

    var body: some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 10) {
                summary

                if session.events.isEmpty {
                    Text("Session registered, no activity yet.")
                        .font(.caption)
                        .foregroundColor(.secondary)
                } else {
                    VStack(alignment: .leading, spacing: 0) {
                        ForEach(Array(displayed.enumerated()), id: \.offset) { _, event in
                            TimelineRow(event: event)
                        }
                    }

                    if eventsNewestFirst.count > Self.inlineLimit {
                        Button {
                            showAll.toggle()
                        } label: {
                            Text(showAll
                                ? "Show recent only"
                                : "Show all \(eventsNewestFirst.count) events")
                                .font(.caption)
                        }
                        .buttonStyle(.borderless)
                    }
                }
            }
            .padding(8)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    private var summary: some View {
        let counts = session.kindCounts
        return HStack(alignment: .firstTextBaseline, spacing: 12) {
            Text(session.projectDir.map { ($0 as NSString).lastPathComponent } ?? "—")
                .font(.subheadline)
                .fontWeight(.semibold)
            Text("started \(session.startTime.formatted(.relative(presentation: .named)))")
                .font(.caption)
                .foregroundColor(.secondary)
            Spacer()
            HStack(spacing: 8) {
                CountBadge(label: "LLM",     value: counts.llmCalls,  color: .blue)
                CountBadge(label: "spawn",   value: counts.spawns,    color: .green)
                CountBadge(label: "read",    value: counts.reads,     color: .yellow)
                CountBadge(label: "write",   value: counts.writes,    color: .orange)
                CountBadge(label: "net",     value: counts.networks,  color: .purple)
                CountBadge(label: "alerts",  value: counts.alerts,    color: .red)
            }
        }
    }
}

// MARK: - Timeline row

private struct TimelineRow: View {
    let event: AgentEvent

    var body: some View {
        HStack(alignment: .top, spacing: 8) {
            Image(systemName: icon)
                .font(.caption2)
                .foregroundColor(color)
                .frame(width: 14)
                .accessibilityHidden(true)

            Text(time)
                .font(.system(.caption2, design: .monospaced))
                .foregroundColor(.secondary)
                .frame(width: 64, alignment: .leading)

            VStack(alignment: .leading, spacing: 1) {
                Text(label)
                    .font(.caption)
                    .foregroundColor(color)
                    .fontWeight(.medium)
                Text(detail)
                    .font(.caption2)
                    .foregroundColor(.primary)
                    .lineLimit(1)
                    .truncationMode(.middle)
                    .textSelection(.enabled)
            }
        }
        .padding(.vertical, 3)
    }

    private var time: String {
        let f = DateFormatter()
        f.dateFormat = "HH:mm:ss"
        return f.string(from: event.timestamp)
    }

    private var icon: String {
        switch event.kind {
        case .llmCall:      return "cloud.fill"
        case .processSpawn: return "play.fill"
        case .fileRead:     return "doc.text"
        case .fileWrite:    return "square.and.pencil"
        case .network:      return "network"
        case .alert:        return "exclamationmark.triangle.fill"
        }
    }

    private var color: Color {
        switch event.kind {
        case .llmCall:      return .blue
        case .processSpawn: return .green
        case .fileRead:     return .yellow
        case .fileWrite:    return .orange
        case .network:      return .purple
        case .alert(_, let severity):
            switch severity {
            case .critical:    return .red
            case .high:        return .orange
            case .medium:      return Color(red: 0.67, green: 0.37, blue: 0.0)
            case .low:         return .blue
            case .informational: return .secondary
            }
        }
    }

    private var label: String {
        switch event.kind {
        case .llmCall(let provider, _, _, _): return "LLM call · \(provider)"
        case .processSpawn:                   return "Spawn"
        case .fileRead:                       return "Read"
        case .fileWrite:                      return "Write"
        case .network:                        return "Network"
        case .alert:                          return "Alert"
        }
    }

    private var detail: String {
        switch event.kind {
        case .llmCall(_, let endpoint, let up, let down):
            var parts = [endpoint]
            if let up   { parts.append("↑\(formatBytes(up))") }
            if let down { parts.append("↓\(formatBytes(down))") }
            return parts.joined(separator: "  ")
        case .processSpawn(let basename, let pid):
            return "\(basename) · pid \(pid)"
        case .fileRead(let path), .fileWrite(let path):
            return path
        case .network(let host, let port):
            return "\(host):\(port)"
        case .alert(let title, let severity):
            return "[\(severity.rawValue)] \(title)"
        }
    }

    private func formatBytes(_ n: Int) -> String {
        if n < 1024 { return "\(n)B" }
        if n < 1024 * 1024 { return "\(n / 1024)KB" }
        return "\(n / (1024 * 1024))MB"
    }
}

// MARK: - Count badge

private struct CountBadge: View {
    let label: String
    let value: Int
    let color: Color

    var body: some View {
        HStack(spacing: 2) {
            Text("\(value)")
                .font(.caption2)
                .fontWeight(.semibold)
                .foregroundColor(value > 0 ? color : .secondary)
            Text(label)
                .font(.caption2)
                .foregroundColor(.secondary)
        }
    }
}
