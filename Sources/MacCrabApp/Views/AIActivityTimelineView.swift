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
    /// Substring filter applied to the displayed timeline rows. Search
    /// is case-insensitive and matches against label + detail text. Does
    /// not affect export (archival, full session) or session-chip counts.
    @State private var searchText: String = ""
    /// Drives the .fileExporter sheet. The exporter is a bare bones
    /// "save as" — formats are picked by the menu choice that arms it.
    @State private var exportPayload: ExportPayload?

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            header

            if appState.aiSessions.isEmpty {
                emptyState
            } else {
                sessionPicker
                searchAndExportBar

                let chosen = selectedSession
                if let session = chosen {
                    SessionTimelineCard(
                        session: session,
                        searchText: searchText
                    )
                }
            }
        }
        .fileExporter(
            isPresented: Binding(
                get: { exportPayload != nil },
                set: { if !$0 { exportPayload = nil } }
            ),
            document: exportPayload.map { TimelineDocument(payload: $0) },
            contentType: exportPayload?.contentType ?? .plainText,
            defaultFilename: exportPayload?.defaultFilename ?? "ai-timeline"
        ) { _ in
            exportPayload = nil
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

    private var searchAndExportBar: some View {
        HStack(spacing: 8) {
            // Search field — filters the displayed rows of the
            // currently-selected session by substring match. Cleared
            // automatically when the user switches sessions (handled
            // via .onChange below).
            HStack(spacing: 4) {
                Image(systemName: "magnifyingglass")
                    .font(.caption)
                    .foregroundColor(.secondary)
                    .accessibilityHidden(true)
                TextField(
                    "Filter timeline…",
                    text: $searchText
                )
                .textFieldStyle(.plain)
                .font(.caption)
                if !searchText.isEmpty {
                    Button {
                        searchText = ""
                    } label: {
                        Image(systemName: "xmark.circle.fill")
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }
                    .buttonStyle(.plain)
                    .accessibilityLabel("Clear search")
                }
            }
            .padding(.horizontal, 6)
            .padding(.vertical, 4)
            .background(
                RoundedRectangle(cornerRadius: 4)
                    .fill(Color.secondary.opacity(0.08))
            )
            .frame(maxWidth: 280)

            Spacer()

            // Export menu — CSV for spreadsheet/SIEM ingest, JSON for
            // structural fidelity (preserves nested kind payloads).
            // Operates on the *full* selected session (not the search-
            // filtered subset) — the search field is a viewing aid, not
            // an export filter.
            Menu {
                Button("Export as CSV") {
                    if let s = selectedSession {
                        exportPayload = .csv(s)
                    }
                }
                Button("Export as JSON") {
                    if let s = selectedSession {
                        exportPayload = .json(s)
                    }
                }
            } label: {
                Label("Export", systemImage: "square.and.arrow.up")
                    .font(.caption)
            }
            .menuStyle(.borderlessButton)
            .frame(width: 90)
            .disabled(selectedSession == nil)
            .accessibilityLabel("Export selected session timeline")
        }
        // Reset the search when the user switches sessions — search
        // semantics are per-session, and stale text would otherwise
        // hide rows in the new session unexpectedly.
        .onChange(of: effectiveSelectedPid) { _ in searchText = "" }
    }

    private var sessionPicker: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 6) {
                // v1.8.0 polish: sort by lastActivity descending so the
                // most recently-active session sits leftmost. Pre-fix
                // the order was the daemon-snapshot order, which made
                // it ambiguous which session came first.
                ForEach(sortedSessions, id: \.aiPid) { session in
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

    private var sortedSessions: [AgentSessionSnapshot] {
        appState.aiSessions.sorted { $0.lastActivity > $1.lastActivity }
    }

    private var effectiveSelectedPid: Int32? {
        if let chosen = selectedPid,
           appState.aiSessions.contains(where: { $0.aiPid == chosen }) {
            return chosen
        }
        return sortedSessions.first?.aiPid
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
            // v1.8.0 polish: surface "started Xm ago" so the picker
            // tells you which session came first without opening each.
            Text("started \(session.startTime.formatted(.relative(presentation: .numeric)))")
                .font(.caption2)
                .foregroundColor(.secondary)
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
    /// Substring filter applied to label + detail. Empty = show all.
    let searchText: String

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

    private var searchFiltered: [AgentEvent] {
        let needle = searchText.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !needle.isEmpty else { return eventsNewestFirst }
        let lc = needle.lowercased()
        return eventsNewestFirst.filter { event in
            agentEventSearchHaystack(event).contains(lc)
        }
    }

    private var displayed: [AgentEvent] {
        showAll
            ? searchFiltered
            : Array(searchFiltered.prefix(Self.inlineLimit))
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
                    // v1.8.0 polish: roll up consecutive same-basename
                    // process spawns within 5s into one row. An AI
                    // session running a tight git/sh/cat loop otherwise
                    // floods the timeline with low-signal "Spawn / sh ·
                    // pid 12345" rows. Cluster threshold = 3+ to avoid
                    // collapsing genuine pairs.
                    let rolled = rollUpSpawns(displayed)
                    // v1.8.0 polish: contain the timeline inside a
                    // fixed-height scroll region so an active session
                    // can't grow the page indefinitely. Other sessions
                    // (and any future sections we add) stay visible
                    // without scrolling the whole tab.
                    ScrollView {
                        VStack(alignment: .leading, spacing: 0) {
                            ForEach(rolled) { item in
                                switch item {
                                case .single(let event):
                                    TimelineRow(event: event)
                                case .spawnCluster(let basename, let events):
                                    SpawnClusterRow(basename: basename, events: events)
                                }
                            }
                        }
                        // v1.8.0 polish: pin VStack to the parent's
                        // width so rows truncate to the visible width
                        // instead of pushing the ScrollView's content
                        // wider than its frame. Pre-fix, a long file
                        // path made the inner content wider than the
                        // viewport, so the ScrollView's vertical
                        // scrollbar landed at the right edge of the
                        // overwide content — visually mid-viewport.
                        .frame(maxWidth: .infinity, alignment: .leading)
                    }
                    .frame(maxHeight: 380)

                    if searchFiltered.isEmpty && !searchText.isEmpty {
                        Text("No events match \"\(searchText)\"")
                            .font(.caption)
                            .foregroundColor(.secondary)
                            .padding(.vertical, 4)
                    }

                    if searchFiltered.count > Self.inlineLimit {
                        Button {
                            showAll.toggle()
                        } label: {
                            Text(showAll
                                ? "Show recent only"
                                : "Show all \(searchFiltered.count) events")
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

// MARK: - Rollup

/// One displayable item in the timeline. Either a single AgentEvent or
/// a cluster of consecutive same-basename process spawns.
private enum TimelineItem: Identifiable {
    case single(AgentEvent)
    case spawnCluster(basename: String, events: [AgentEvent])

    var id: String {
        switch self {
        case .single(let e):
            // (timestamp + kind) is unique per event; using timestamp
            // alone collides if two kinds fire in the same millisecond.
            return "s-\(e.timestamp.timeIntervalSince1970)-\(kindKey(e.kind))"
        case .spawnCluster(let basename, let events):
            let first = events.first?.timestamp.timeIntervalSince1970 ?? 0
            return "c-\(basename)-\(first)-\(events.count)"
        }
    }

    private func kindKey(_ kind: AgentEvent.Kind) -> String {
        switch kind {
        case .llmCall:      return "llm"
        case .processSpawn: return "spawn"
        case .fileRead:     return "read"
        case .fileWrite:    return "write"
        case .network:      return "net"
        case .alert:        return "alert"
        }
    }
}

/// Walk the (newest-first) timeline collapsing runs of same-basename
/// processSpawn events that occur within 5s of each other. Anything
/// non-spawn — or spawns of a different basename, or spawns more than
/// 5s apart — terminates the cluster. Singletons and pairs stay as
/// individual rows; only 3+ collapse.
private func rollUpSpawns(_ events: [AgentEvent]) -> [TimelineItem] {
    let clusterMinSize = 3
    let clusterWindowSec: TimeInterval = 5

    var result: [TimelineItem] = []
    var i = 0
    while i < events.count {
        let event = events[i]
        guard case .processSpawn(let basename, _) = event.kind else {
            result.append(.single(event))
            i += 1
            continue
        }

        // Collect contiguous same-basename spawns within the time
        // window. `events` is newest-first, so "next" goes back in
        // time and the timestamp delta is computed accordingly.
        var cluster: [AgentEvent] = [event]
        var j = i + 1
        while j < events.count {
            let next = events[j]
            guard case .processSpawn(let nextBasename, _) = next.kind,
                  nextBasename == basename
            else { break }
            let delta = cluster.last!.timestamp.timeIntervalSince(next.timestamp)
            if delta > clusterWindowSec { break }
            cluster.append(next)
            j += 1
        }

        if cluster.count >= clusterMinSize {
            result.append(.spawnCluster(basename: basename, events: cluster))
            i = j
        } else {
            result.append(.single(event))
            i += 1
        }
    }
    return result
}

// MARK: - Spawn cluster row

private struct SpawnClusterRow: View {
    let basename: String
    /// Newest-first; first element is the most recent spawn.
    let events: [AgentEvent]

    var body: some View {
        HStack(alignment: .top, spacing: 8) {
            Image(systemName: "play.fill")
                .font(.caption2)
                .foregroundColor(.green)
                .frame(width: 14)
                .accessibilityHidden(true)

            Text(timeRange)
                .font(.system(.caption2, design: .monospaced))
                .foregroundColor(.secondary)
                .frame(width: 120, alignment: .leading)

            VStack(alignment: .leading, spacing: 1) {
                HStack(spacing: 6) {
                    Text("Spawn")
                        .font(.caption)
                        .foregroundColor(.green)
                        .fontWeight(.medium)
                    Text("×\(events.count)")
                        .font(.caption2)
                        .foregroundColor(.secondary)
                        .padding(.horizontal, 4)
                        .padding(.vertical, 1)
                        .background(
                            RoundedRectangle(cornerRadius: 3)
                                .fill(Color.green.opacity(0.12))
                        )
                }
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

    private var timeRange: String {
        let f = DateFormatter()
        f.dateFormat = "HH:mm:ss"
        // Cluster is newest-first: oldest is last, newest is first.
        guard let oldest = events.last?.timestamp,
              let newest = events.first?.timestamp else { return "" }
        let a = f.string(from: oldest)
        let b = f.string(from: newest)
        return a == b ? a : "\(a)–\(b)"
    }

    private var detail: String {
        // Pull pids from each event, sort ascending, render compactly.
        // For a tight cluster (e.g., pid 12340..12347) show as a range;
        // for a sparse cluster fall back to a comma-separated list.
        let pids: [Int32] = events.compactMap {
            if case .processSpawn(_, let pid) = $0.kind { return pid } else { return nil }
        }
        guard !pids.isEmpty else { return basename }
        let sorted = pids.sorted()
        // Range if every pid is contiguous (sorted[i] == sorted[0]+i).
        let isRange = sorted.enumerated().allSatisfy { idx, p in p == sorted[0] + Int32(idx) }
        if isRange && sorted.count > 2 {
            return "\(basename) · pids \(sorted.first!)–\(sorted.last!)"
        }
        let preview = sorted.prefix(6).map(String.init).joined(separator: ", ")
        let suffix = sorted.count > 6 ? ", …" : ""
        return "\(basename) · pids \(preview)\(suffix)"
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

// MARK: - Search

/// Lowercased haystack for substring matching. Includes the kind name,
/// the human label, and the detail string so a single search box
/// covers all the obvious queries (path fragments, process basenames,
/// network host:port pairs, alert titles).
private func agentEventSearchHaystack(_ event: AgentEvent) -> String {
    var parts: [String] = []
    switch event.kind {
    case .llmCall(let provider, let endpoint, _, _):
        parts.append("llm")
        parts.append(provider)
        parts.append(endpoint)
    case .processSpawn(let basename, let pid):
        parts.append("spawn")
        parts.append(basename)
        parts.append(String(pid))
    case .fileRead(let path):
        parts.append("read")
        parts.append(path)
    case .fileWrite(let path):
        parts.append("write")
        parts.append(path)
    case .network(let host, let port):
        parts.append("network")
        parts.append(host)
        parts.append(String(port))
    case .alert(let title, let severity):
        parts.append("alert")
        parts.append(title)
        parts.append(severity.rawValue)
    }
    return parts.joined(separator: " ").lowercased()
}

// MARK: - Export

import UniformTypeIdentifiers

/// Wraps a session + chosen format. The .fileExporter sheet binds to a
/// non-nil instance; setting it nil dismisses the sheet.
enum ExportPayload: Hashable {
    case csv(AgentSessionSnapshot)
    case json(AgentSessionSnapshot)

    var contentType: UTType {
        switch self {
        case .csv:  return .commaSeparatedText
        case .json: return .json
        }
    }

    var defaultFilename: String {
        let session = self.session
        let stamp = ISO8601DateFormatter().string(from: session.startTime)
            .replacingOccurrences(of: ":", with: "-")
        let toolSlug = session.toolType.displayName
            .lowercased()
            .replacingOccurrences(of: " ", with: "-")
        return "ai-timeline-\(toolSlug)-pid\(session.aiPid)-\(stamp)"
    }

    var session: AgentSessionSnapshot {
        switch self {
        case .csv(let s), .json(let s): return s
        }
    }

    func render() -> Data {
        switch self {
        case .csv(let s):  return Self.renderCSV(s).data(using: .utf8) ?? Data()
        case .json(let s): return (try? Self.renderJSON(s)) ?? Data()
        }
    }

    private static func renderCSV(_ session: AgentSessionSnapshot) -> String {
        // CSV header keeps the same shape the SIEM-export view uses
        // for alerts, so analysts pivoting from one to the other don't
        // hit a different schema. raw_payload column carries the
        // kind-specific extras that don't fit indexed columns.
        var out = "timestamp_iso,kind,process_or_provider,pid,path_or_endpoint,host,port,severity,raw_payload\n"
        let isoFormatter = ISO8601DateFormatter()
        isoFormatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        for event in session.events {
            let ts = isoFormatter.string(from: event.timestamp)
            switch event.kind {
            case .llmCall(let provider, let endpoint, let up, let down):
                let payload = "up=\(up.map(String.init) ?? "");down=\(down.map(String.init) ?? "")"
                out += "\(csvEscape(ts)),llm_call,\(csvEscape(provider)),,\(csvEscape(endpoint)),,,,\(csvEscape(payload))\n"
            case .processSpawn(let basename, let pid):
                out += "\(csvEscape(ts)),process_spawn,\(csvEscape(basename)),\(pid),,,,,\n"
            case .fileRead(let path):
                out += "\(csvEscape(ts)),file_read,,,\(csvEscape(path)),,,,\n"
            case .fileWrite(let path):
                out += "\(csvEscape(ts)),file_write,,,\(csvEscape(path)),,,,\n"
            case .network(let host, let port):
                out += "\(csvEscape(ts)),network,,,,\(csvEscape(host)),\(port),,\n"
            case .alert(let title, let severity):
                out += "\(csvEscape(ts)),alert,,,,,,\(severity.rawValue),\(csvEscape(title))\n"
            }
        }
        return out
    }

    private static func renderJSON(_ session: AgentSessionSnapshot) throws -> Data {
        // Pass the snapshot through JSONEncoder. AgentSessionSnapshot
        // is already Codable so this preserves nested kind enum
        // payloads exactly.
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        return try encoder.encode(session)
    }

    private static func csvEscape(_ s: String) -> String {
        // Quote + double any embedded quotes if the value needs it.
        // RFC 4180 quoting; cheap to apply unconditionally where needed.
        if s.contains(",") || s.contains("\"") || s.contains("\n") {
            return "\"\(s.replacingOccurrences(of: "\"", with: "\"\""))\""
        }
        return s
    }
}

/// Bare-bones FileDocument that emits the pre-rendered bytes from an
/// ExportPayload. ReferenceFileDocument would offer per-write progress
/// / undo support, but we don't need either for a one-shot save.
struct TimelineDocument: FileDocument {
    static var readableContentTypes: [UTType] = [.commaSeparatedText, .json]
    let payload: ExportPayload

    init(payload: ExportPayload) { self.payload = payload }

    init(configuration: ReadConfiguration) throws {
        // Read isn't a meaningful operation for export-only docs;
        // provide a stub so the protocol is satisfied. The sheet
        // path never invokes this initializer.
        throw CocoaError(.featureUnsupported)
    }

    func fileWrapper(configuration: WriteConfiguration) throws -> FileWrapper {
        FileWrapper(regularFileWithContents: payload.render())
    }
}
