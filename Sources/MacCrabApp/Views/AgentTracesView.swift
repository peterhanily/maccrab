// AgentTracesView.swift
// MacCrabApp
//
// v1.9 PR-4 — dashboard panel for the Agent Traces feature. Shows the
// recent traces that the OTLP receiver has ingested, per-trace span
// timelines, and the running attribution-quality metric.
//
// Pass 7 panel-richness contract: search + drill-down (selectedTraceId
// drives the detail pane). Empty state explicitly explains how to enable
// the feature so the panel is never just blank.

import SwiftUI
import MacCrabCore

struct AgentTracesView: View {
    @ObservedObject var appState: AppState

    @State private var searchText: String = ""

    private var filteredTraceIds: [String] {
        guard !searchText.isEmpty else { return appState.recentTraceIds }
        let q = searchText.lowercased()
        return appState.recentTraceIds.filter { $0.lowercased().contains(q) }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header
            if appState.recentTraceIds.isEmpty {
                emptyState
            } else {
                HSplitView {
                    traceList
                    detailPane
                }
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .task {
            await appState.refreshAgentTraces()
        }
    }

    // MARK: Header

    private var header: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text(String(localized: "agentTraces.title",
                             defaultValue: "Agent Traces"))
                    .font(.title2).fontWeight(.bold)
                Spacer()
                Button {
                    Task {
                        await appState.refreshAgentTraces(force: true)
                        appState.refreshAgentTracesStatus()
                    }
                } label: {
                    Label(String(localized: "agentTraces.refresh", defaultValue: "Refresh"),
                          systemImage: "arrow.clockwise")
                }
                .buttonStyle(.bordered)
                .controlSize(.small)
            }

            // v1.9 Phase-3.3: receiver toggle + status. Toggling writes
            // ~/Library/.../agent_traces_config.json and SIGHUPs the
            // daemon, which reloads + starts/stops the receiver to
            // match. Status badge reflects the latest snapshot the
            // daemon published.
            receiverControlRow

            Text(String(localized: "agentTraces.subtitle",
                         defaultValue: "Each trace is one AI-agent interaction. The kernel events MacCrab observed underneath that interaction can be matched by trace_id."))
                .font(.callout)
                .foregroundStyle(.secondary)

            Text(String(localized: "agentTraces.statsLegend",
                         defaultValue: "Spans = OTLP receiver activity. Rated / total / accuracy = kernel events with machine attribution that an operator has reviewed."))
                .font(.caption2)
                .foregroundStyle(.secondary)

            // v1.9 Phase-6.2 final ship copy. Phase-2.2 wired
            // column-level AES-GCM, Phase-3 added the in-panel toggle,
            // Phase-5 hardened the threat-intel pathway. No
            // experimental caveats remain.
            HStack(alignment: .top, spacing: 6) {
                Image(systemName: "lock.shield.fill")
                    .font(.caption2)
                    .foregroundStyle(.green)
                VStack(alignment: .leading, spacing: 2) {
                    Text(String(localized: "agentTraces.privacyTitle",
                                 defaultValue: "Local-only · sanitised · AES-GCM at rest"))
                        .font(.caption2)
                        .fontWeight(.semibold)
                    Text(String(localized: "agentTraces.privacyBody",
                                 defaultValue: "Span attribute values pass through the secret-shape sanitiser, then AES-GCM-encrypted under the same shared key as events.db. Tamper detection is built in. Spans only ever leave your Mac if you configure your AI tool to export to this receiver."))
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
                Spacer()
            }
            .padding(8)
            .background(Color.green.opacity(0.06))
            .clipShape(RoundedRectangle(cornerRadius: 6))

            HStack {
                Image(systemName: "magnifyingglass")
                    .foregroundStyle(.secondary)
                TextField(
                    String(localized: "agentTraces.searchPlaceholder",
                            defaultValue: "Search by trace_id…"),
                    text: $searchText
                )
                .textFieldStyle(.roundedBorder)
            }

            statsBar
        }
        .padding()
    }

    /// v1.9 Phase-3.3: receiver enable toggle + status pill.
    private var receiverControlRow: some View {
        HStack(spacing: 12) {
            Toggle(isOn: Binding(
                get: { appState.agentTracesReceiverEnabled },
                set: { newValue in
                    appState.agentTracesReceiverEnabled = newValue
                    appState.scheduleAgentTracesSync()
                }
            )) {
                VStack(alignment: .leading, spacing: 1) {
                    Text(String(localized: "agentTraces.toggleTitle",
                                 defaultValue: "Receive agent traces on 127.0.0.1:4318"))
                        .fontWeight(.medium)
                    Text(String(localized: "agentTraces.toggleHint",
                                 defaultValue: "Starts a loopback-only OTLP/HTTP receiver. Configure your AI tool to export to http://127.0.0.1:4318."))
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
            }
            .toggleStyle(.switch)

            Spacer()

            statusPill
        }
        .padding(8)
        .background(Color.secondary.opacity(0.06))
        .clipShape(RoundedRectangle(cornerRadius: 6))
        .task {
            appState.refreshAgentTracesStatus()
        }
    }

    @ViewBuilder
    private var statusPill: some View {
        // v1.9.0 (audit UX-H5): wrap in a TimelineView so the pill
        // re-renders every 5 s without us threading a Timer through
        // AppState. Lets the "Awaiting daemon" → "Daemon not
        // responding" transition land on time even when no other
        // state has changed.
        TimelineView(.periodic(from: .now, by: 5)) { context in
            statusPillContents(now: context.date)
        }
    }

    @ViewBuilder
    private func statusPillContents(now: Date) -> some View {
        if let status = appState.agentTracesStatus {
            HStack(spacing: 4) {
                Circle()
                    .fill(status.running ? Color.green : Color.secondary)
                    .frame(width: 8, height: 8)
                Text(
                    status.running
                        ? String(localized: "agentTraces.statusRunning",
                                  defaultValue: "Running on \(Int(status.port))")
                        : String(localized: "agentTraces.statusStopped",
                                  defaultValue: "Stopped")
                )
                .font(.caption2)
                if let err = status.lastError, !status.running {
                    Image(systemName: "exclamationmark.triangle.fill")
                        .font(.caption2)
                        .foregroundStyle(.orange)
                        .help(err)
                }
            }
            .padding(.horizontal, 8).padding(.vertical, 4)
            .background(Capsule().fill(Color.secondary.opacity(0.1)))
        } else if appState.agentTracesReceiverEnabled {
            // Toggle is on but no status yet. After
            // `agentTracesAwaitingTimeoutSeconds` we flip from orange
            // "Awaiting daemon" to red "Daemon not responding" with a
            // help tooltip so the user knows the next step.
            let isStale: Bool = {
                guard let requested = appState.agentTracesEnableRequestedAt
                else { return false }
                return now.timeIntervalSince(requested)
                    > AppState.agentTracesAwaitingTimeoutSeconds
            }()
            if isStale {
                HStack(spacing: 4) {
                    Circle().fill(Color.red).frame(width: 8, height: 8)
                    Text(String(localized: "agentTraces.statusNotResponding",
                                 defaultValue: "Daemon not responding"))
                        .font(.caption2)
                    Image(systemName: "questionmark.circle")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                        .help(String(localized: "agentTraces.statusNotRespondingHelp",
                                      defaultValue: "The dashboard hasn't seen a status snapshot from the daemon since you enabled the receiver. The daemon may not be running, the system extension may need to be re-activated (Settings → System Extension), or the daemon may be a v1.8.x build that doesn't speak the agent-traces protocol. Check Console.app filtered to com.maccrab.agentkit for details."))
                }
                .padding(.horizontal, 8).padding(.vertical, 4)
                .background(Capsule().fill(Color.red.opacity(0.1)))
            } else {
                HStack(spacing: 4) {
                    Circle().fill(Color.orange).frame(width: 8, height: 8)
                    Text(String(localized: "agentTraces.statusUnknown",
                                 defaultValue: "Awaiting daemon"))
                        .font(.caption2)
                }
                .padding(.horizontal, 8).padding(.vertical, 4)
                .background(Capsule().fill(Color.orange.opacity(0.1)))
            }
        }
    }

    private var statsBar: some View {
        let stats = appState.attributionStats
        // Span count comes from `traces.db` (OTLP receiver activity);
        // attribution counts come from `events.db` (kernel events the
        // detection engine machine-attributed). Showing both side-by-
        // side so a populated trace list and "0 rated" stats no longer
        // look contradictory.
        let spanCount = appState.recentTraceIds.count
        return HStack(spacing: 16) {
            statCell(
                title: String(localized: "agentTraces.statTraces",
                              defaultValue: "Traces"),
                value: "\(spanCount)",
                source: String(localized: "agentTraces.statSourceOtlp",
                                defaultValue: "OTLP")
            )
            Divider().frame(height: 28)
            statCell(
                title: String(localized: "agentTraces.statTotal",
                              defaultValue: "Events with machine attribution"),
                value: "\(stats.totalEventsWithMachineAttribution)",
                source: String(localized: "agentTraces.statSourceEs",
                                defaultValue: "ES")
            )
            statCell(
                title: String(localized: "agentTraces.statRated",
                              defaultValue: "Rated"),
                value: "\(stats.ratedCount)",
                source: nil
            )
            statCell(
                title: String(localized: "agentTraces.statAcc",
                              defaultValue: "Accuracy among rated"),
                value: stats.accuracyAmongRated.map { String(format: "%.0f%%", $0 * 100) } ?? "—",
                source: nil
            )
            Spacer()
        }
        .padding(.top, 4)
    }

    @ViewBuilder
    private func statCell(title: String, value: String, source: String?) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            HStack(spacing: 4) {
                Text(value).font(.headline)
                if let source {
                    Text(source)
                        .font(.system(size: 9, weight: .semibold))
                        .padding(.horizontal, 4)
                        .padding(.vertical, 1)
                        .background(Color.secondary.opacity(0.12))
                        .clipShape(Capsule())
                        .foregroundStyle(.secondary)
                }
            }
            Text(title).font(.caption).foregroundStyle(.secondary)
        }
    }

    // MARK: Empty state

    private var emptyState: some View {
        VStack(spacing: 12) {
            Image(systemName: "scope")
                .font(.system(size: 48))
                .foregroundStyle(.secondary)
            Text(String(localized: "agentTraces.emptyTitle",
                         defaultValue: "No agent traces yet"))
                .font(.headline)
            Text(String(localized: "agentTraces.emptyHint",
                         defaultValue: "Toggle the receiver on with the switch above, then point your AI tool's OTel exporter at http://127.0.0.1:4318. Claude Code: set CLAUDE_CODE_ENABLE_TELEMETRY=1, OTEL_TRACES_EXPORTER=otlp, OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf, OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:4318. See docs/AGENT_TRACES.md."))
                .font(.callout)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .frame(maxWidth: 480)
                .padding(.horizontal)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    // MARK: Trace list (left pane)

    private var traceList: some View {
        List(filteredTraceIds, id: \.self, selection: $appState.selectedTraceId) { traceId in
            VStack(alignment: .leading, spacing: 2) {
                Text(traceId)
                    .font(.system(.body, design: .monospaced))
                    .lineLimit(1)
                    .truncationMode(.middle)
            }
            .padding(.vertical, 4)
            .tag(traceId)
            // v1.9 Phase-4.5: VoiceOver friendliness. The default
            // accessibility label was the raw 32-hex string read
            // character by character. The "ending in" form gives a
            // distinct audio handle while still letting the user
            // disambiguate when several traces share a prefix.
            .accessibilityLabel(
                "Trace ending in \(String(traceId.suffix(8))). Click to view spans."
            )
        }
        .listStyle(.bordered)
        .frame(minWidth: 320, idealWidth: 360, maxWidth: 480)
        .onChange(of: appState.selectedTraceId) { newValue in
            guard let id = newValue else { return }
            Task { await appState.loadTrace(id) }
        }
    }

    // MARK: Detail pane (right)

    private var detailPane: some View {
        Group {
            if appState.selectedTraceId == nil {
                placeholderDetail
            } else if appState.selectedTraceSpans.isEmpty {
                ProgressView()
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                traceDetail
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private var placeholderDetail: some View {
        VStack(spacing: 8) {
            Image(systemName: "rectangle.dashed")
                .font(.system(size: 32))
                .foregroundStyle(.secondary)
            Text(String(localized: "agentTraces.selectTrace",
                         defaultValue: "Select a trace to view its spans"))
                .foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private var traceDetail: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 12) {
                if let id = appState.selectedTraceId {
                    HStack(spacing: 6) {
                        Image(systemName: "scope")
                            .foregroundStyle(.tint)
                        Text(id)
                            .font(.system(.callout, design: .monospaced))
                            .textSelection(.enabled)
                    }
                }
                // v1.9 Phase-4.3: ordering / indent legend so the
                // visual hierarchy is self-explanatory.
                Text(String(localized: "agentTraces.spansLegend",
                             defaultValue: "Ordered by start time, indented by parent depth."))
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                Divider()
                let depths = Self.computeDepths(spans: appState.selectedTraceSpans)
                ForEach(appState.selectedTraceSpans, id: \.spanId) { span in
                    spanRow(span, depth: depths[span.spanId] ?? 0)
                }
            }
            .padding()
        }
    }

    /// Compute parent-chain depth for each span. Root spans (no
    /// parent_span_id, OR parent_span_id not in this trace) are 0;
    /// children +1 per hop. Bounded to 8 to prevent runaway depth in
    /// pathological data.
    private static func computeDepths(spans: [SpanRecord]) -> [String: Int] {
        let bySpanId: [String: SpanRecord] = Dictionary(uniqueKeysWithValues: spans.map { ($0.spanId, $0) })
        var depths: [String: Int] = [:]
        func depth(of span: SpanRecord, visiting: Set<String>) -> Int {
            if let cached = depths[span.spanId] { return cached }
            guard let parentId = span.parentSpanId,
                  let parent = bySpanId[parentId],
                  !visiting.contains(parentId) else {
                depths[span.spanId] = 0
                return 0
            }
            let d = min(8, 1 + depth(of: parent, visiting: visiting.union([span.spanId])))
            depths[span.spanId] = d
            return d
        }
        for span in spans { _ = depth(of: span, visiting: []) }
        return depths
    }

    @ViewBuilder
    private func spanRow(_ span: SpanRecord, depth: Int) -> some View {
        // v1.9 Phase-4.3: indent by parent depth so a multi-level
        // tool→sub-tool→bash chain reads as a tree at a glance.
        // 16pt per level, capped via computeDepths so a malformed
        // trace can't drive layout off-screen.
        HStack(alignment: .top, spacing: 0) {
            if depth > 0 {
                Spacer().frame(width: CGFloat(depth) * 16)
            }
            VStack(alignment: .leading, spacing: 4) {
                HStack(spacing: 8) {
                    Image(systemName: span.parentSpanId == nil ? "play.circle" : "arrow.turn.down.right")
                        .foregroundStyle(.tint)
                    Text(span.spanName)
                        .font(.headline)
                    Spacer()
                    if let tool = span.agentTool {
                        Text(tool.displayName)
                            .font(.caption)
                            .padding(.horizontal, 6)
                            .padding(.vertical, 2)
                            .background(Color.accentColor.opacity(0.1))
                            .clipShape(Capsule())
                    }
                }
                HStack(spacing: 12) {
                    Text("span_id: \(span.spanId)")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                    if let parent = span.parentSpanId {
                        Text("parent: \(parent)")
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                    }
                    Text(durationLabel(start: span.startNs, end: span.endNs))
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
                if let svc = span.serviceName {
                    Text("service.name: \(svc)")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
                if let json = span.attributesJson, !json.isEmpty {
                    DisclosureGroup(String(localized: "agentTraces.attributes", defaultValue: "attributes")) {
                        // v1.9 Phase-4.2: pretty-print before display.
                        // Sanitiser/encryption produce compact JSON; a
                        // 1000-char one-liner is unreadable.
                        Text(Self.prettyJson(json))
                            .font(.system(.caption2, design: .monospaced))
                            .textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .padding(6)
                            .background(Color.secondary.opacity(0.08))
                            .clipShape(RoundedRectangle(cornerRadius: 4))
                    }
                    .font(.caption2)
                }
            }
            .padding(8)
            .background(Color.secondary.opacity(0.05))
            .clipShape(RoundedRectangle(cornerRadius: 6))
        }
    }

    /// Pretty-printed JSON. Falls back to the raw string if the input
    /// isn't valid JSON (e.g. legacy plaintext rows that pre-date the
    /// sanitiser, or partially-corrupted data).
    private static func prettyJson(_ raw: String) -> String {
        guard let data = raw.data(using: .utf8),
              let obj = try? JSONSerialization.jsonObject(with: data, options: []),
              let pretty = try? JSONSerialization.data(
                  withJSONObject: obj,
                  options: [.prettyPrinted, .sortedKeys]
              ),
              let s = String(data: pretty, encoding: .utf8) else {
            return raw
        }
        return s
    }

    private func durationLabel(start: UInt64, end: UInt64) -> String {
        guard end > start else { return "" }
        let durNs = end - start
        if durNs < 1_000_000 {
            return "\(durNs / 1_000) µs"
        } else if durNs < 1_000_000_000 {
            return "\(durNs / 1_000_000) ms"
        } else {
            return String(format: "%.2fs", Double(durNs) / 1e9)
        }
    }
}
