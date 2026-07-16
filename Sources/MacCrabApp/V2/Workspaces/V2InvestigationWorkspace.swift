// V2InvestigationWorkspace.swift
// Spec §7.3 — process / trace / event / hunt / AI analysis.

import SwiftUI

struct V2InvestigationWorkspace: View {
    @ObservedObject var state: V2DashboardState
    @ObservedObject var appState: AppState
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var selectedTrace: V2MockTrace?
    @State private var traces: [V2MockTrace] = []
    @State private var recentAlerts: [V2MockAlert] = []
    // F2: engine LLM health, refreshed off-main by reload() rather than read
    // synchronously in the view body on every re-evaluation.
    @State private var engineHeartbeat: V2HeartbeatSnapshot?
    @State private var traceMembersCache: [String: [V2TraceMember]] = [:]
    @State private var hoveredMemberId: String? = nil
    @State private var selectedMemberId: String? = nil
    @State private var graphAsList: Bool = false
    @State private var copiedToast: Bool = false
    /// Active layout algorithm for the trace graph. Defaults to radial
    /// (anchor at centre, members on a ring); user can switch via the
    /// top-left segmented control. The chosen layout drives
    /// `computePositions(...)`; once the user drags a node, that node's
    /// position is committed to `customPositions` and the layout
    /// switches to `.manual` so subsequent layout passes don't fight
    /// the user's drag.
    @State private var graphLayout: V2TraceLayout = .radial
    @State private var customPositions: [String: CGPoint] = [:]
    /// Owned shared drag-positions model. Stored as @State (the
    /// reference) NOT @StateObject, so observing the @Published
    /// changes is opt-in per child view: DraggableMemberNode WRITES
    /// (via callback) but doesn't observe — it has its own local
    /// @State for visual offset; only EdgeOverlay observes, so the
    /// edge canvas redraws with each drag frame while the parent +
    /// other nodes do not. Pre-fix the edges only updated on drag
    /// end because the Canvas was reading the static `positions`
    /// dict, not the in-flight drag offsets.
    @State private var dragModel = DragPositionsModel()
    @State private var graphZoom: CGFloat = 1.0
    @State private var pinchBaseline: CGFloat = 1.0
    /// Cached layout positions keyed by (layout, traceId, canvas-w, canvas-h, member-count).
    /// Without this cache the body re-evaluation during a drag (every
    /// frame) re-ran the force-directed solver — 200 iters × N² — and
    /// the dashboard beachballed for any trace with >12 nodes. Now
    /// we only recompute when the input genuinely changed.
    @State private var cachedPositions: [String: CGPoint] = [:]
    @State private var cachedPositionKey: String = ""
    private let zoomMin: CGFloat = 0.4
    private let zoomMax: CGFloat = 2.6
    /// Trace inspector visibility. The X button on the inspector
    /// flips this to false; switching to a different trace via the
    /// picker re-opens it. Without a separate hidden flag, clicking
    /// X just nilled `selectedTrace` and the view fell back to
    /// `traces.first` — looking like the inspector had jumped to
    /// the first trace instead of closing.
    @State private var traceInspectorOpen: Bool = true
    @State private var tracePickerOpen: Bool = false
    @State private var tracePickerQuery: String = ""

    init(state: V2DashboardState, appState: AppState) {
        self.state = state
        self.appState = appState
    }

    private func reload() async {
        // v1.12.6 Wave 9P: write each piece of @State as soon as
        // its await resolves so the trailing MainActor.run race
        // (Wave 9G shape) can't drop both writes.
        let t = await state.provider.traces(limit: 50)
        await MainActor.run {
            self.traces = t
            // D6: cross-workspace deep-link (palette `trace:` link,
            // notification, or a trace: deep link) requests a specific
            // trace by id via selectedEntities. Drain it here so it wins
            // on arrival, mirroring how Alerts/Detection consume their
            // keys. Clearing the key means the drain fires once — later
            // reloads fall through to the #17 pin below and keep the
            // user's selection rather than re-forcing the deep-link target.
            // entityKey format matches V2DashboardState.entityKey:
            // "<workspace>:<tab>" or just "<workspace>".
            var deepLinked = false
            let candidateKeys = ["investigation:investigationTraceGraph", "investigation"]
            for key in candidateKeys {
                if let pendingId = state.selectedEntities[key],
                   let match = t.first(where: { $0.id == pendingId }) {
                    self.selectedTrace = match
                    self.traceInspectorOpen = true
                    state.selectedEntities[key] = nil
                    deepLinked = true
                    break
                }
            }
            // #17: pin / preserve the selected trace across the 5 s
            // reload. Pre-fix `selectedTrace` stayed nil and every
            // render fell back to `traces.first`; when a reload reordered
            // the list (a newly-anchored trace jumping to the front) the
            // graph / inspector / in-flight drag silently swapped to a
            // different trace mid-interaction. Now: first load pins the
            // freshest trace; later reloads keep the user's current
            // selection (refreshed to the new snapshot), only falling
            // back to the freshest when no selection exists yet.
            if !deepLinked {
                if let current = self.selectedTrace {
                    self.selectedTrace = t.first(where: { $0.id == current.id }) ?? current
                } else {
                    self.selectedTrace = t.first
                }
            }
        }

        let a = await state.provider.alerts(limit: 30)
        await MainActor.run {
            self.recentAlerts = a
                .filter { $0.severity == .critical || $0.severity == .high }
                .prefix(8)
                .map { $0 }
        }

        // F2: heartbeat() reads the file off-main; cache the result so the
        // AI Analysis tab doesn't read+parse it synchronously per body eval.
        let hb = await state.provider.heartbeat()
        await MainActor.run { self.engineHeartbeat = hb }
    }

    /// Export the current trace as a .maccrabtrace bundle. Shells
    /// out to `maccrabctl trace export` because the in-process
    /// exporter needs the full trace + memberships + entities + edges
    /// pipeline that maccrabctl already implements end-to-end.
    private func exportTrace(_ trace: V2MockTrace) {
        let panel = NSSavePanel()
        panel.title = "Export trace bundle"
        panel.nameFieldStringValue = "\(trace.id).maccrabtrace"
        panel.allowedContentTypes = [.data]
        panel.begin { response in
            guard response == .OK, let url = panel.url else { return }
            DispatchQueue.global(qos: .userInitiated).async {
                let result = V2InvestigationWorkspace.runMaccrabctl(
                    arguments: ["trace", "export", trace.id, "--output", url.path]
                )
                DispatchQueue.main.async {
                    if result.exitCode == 0 {
                        state.showToast(V2Toast(
                            kind: .success,
                            title: "Bundle exported",
                            detail: url.lastPathComponent
                        ))
                    } else {
                        state.showToast(V2Toast(
                            kind: .error,
                            title: "Export failed",
                            detail: result.stderr.split(separator: "\n").first.map(String.init)
                                ?? "exit code \(result.exitCode)"
                        ))
                    }
                }
            }
        }
    }

    /// Verify an exported .maccrabtrace bundle. Shells out to
    /// `maccrabctl trace verify` so we get the same exit codes and
    /// guarantees as the CLI. Default directory is the user's
    /// Documents folder, where Export defaults to.
    private func verifyBundle() {
        let panel = NSOpenPanel()
        panel.title = "Verify exported trace bundle"
        panel.message = "Pick a previously exported .maccrabtrace bundle to verify its schema, Merkle root, and signature."
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        panel.allowedContentTypes = [.data]
        panel.allowsOtherFileTypes = true
        panel.directoryURL = FileManager.default
            .urls(for: .documentDirectory, in: .userDomainMask).first
        panel.begin { response in
            guard response == .OK, let url = panel.url else { return }
            DispatchQueue.global(qos: .userInitiated).async {
                let result = V2InvestigationWorkspace.runMaccrabctl(
                    arguments: ["trace", "verify", url.path]
                )
                DispatchQueue.main.async {
                    if result.exitCode == 0 {
                        state.showToast(V2Toast(
                            kind: .success,
                            title: "Bundle verified",
                            detail: url.lastPathComponent
                        ))
                    } else {
                        state.showToast(V2Toast(
                            kind: .error,
                            title: "Verification failed (exit \(result.exitCode))",
                            detail: result.stdout.split(separator: "\n").first.map(String.init)
                                ?? result.stderr.split(separator: "\n").first.map(String.init)
                                ?? "see maccrabctl trace verify"
                        ))
                    }
                }
            }
        }
    }

    /// Locate the `maccrabctl` binary across the common install
    /// paths and run it. The dashboard ships with it inside the app
    /// bundle's Contents/Resources/bin/ for stable invocation.
    private static func runMaccrabctl(arguments: [String])
        -> (exitCode: Int32, stdout: String, stderr: String)
    {
        let candidates = [
            Bundle.main.path(forResource: "maccrabctl", ofType: nil, inDirectory: "bin"),
            Bundle.main.path(forResource: "maccrabctl", ofType: nil),
            "/usr/local/bin/maccrabctl",
            "/opt/homebrew/bin/maccrabctl",
            FileManager.default.currentDirectoryPath + "/.build/debug/maccrabctl",
        ].compactMap { $0 }
        guard let binPath = candidates.first(where: { FileManager.default.isExecutableFile(atPath: $0) }) else {
            return (127, "", "maccrabctl binary not found in any known path")
        }
        let task = Process()
        task.executableURL = URL(fileURLWithPath: binPath)
        task.arguments = arguments
        let outPipe = Pipe(); let errPipe = Pipe()
        task.standardOutput = outPipe
        task.standardError = errPipe
        do {
            try task.run()
            task.waitUntilExit()
            let outData = (try? outPipe.fileHandleForReading.readToEnd()) ?? Data()
            let errData = (try? errPipe.fileHandleForReading.readToEnd()) ?? Data()
            return (
                task.terminationStatus,
                String(data: outData, encoding: .utf8) ?? "",
                String(data: errData, encoding: .utf8) ?? ""
            )
        } catch {
            return (-1, "", "spawn failed: \(error)")
        }
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            V2WorkspaceTabStrip(
                tabs: V2Workspace.investigation.tabs,
                selected: Binding(
                    get: { state.selectedTabs[.investigation] ?? .investigationTraceGraph },
                    set: { if let v = $0 { state.selectedTabs[.investigation] = v } }
                )
            )
            tabBody
        }
        .task(id: "\(state.provider.mode):\(state.refreshTick)") { await reload() }
    }

    @ViewBuilder
    private var tabBody: some View {
        switch state.selectedTabs[.investigation] ?? .investigationTraceGraph {
        case .investigationTraceGraph:        traceGraphTab
        case .investigationAgentTraces:       agentTracesTab
        case .investigationAIAnalysis:        aiAnalysisTab
        // v1.17.2: the Investigation→Forensics tabs were removed (Forensics is
        // its own workspace). A stale persisted selection falls back here.
        default: traceGraphTab
        }
    }

    // MARK: - TraceGraph

    private var traceGraphTab: some View {
        // v1.12.9: floating inspector overlay (see V2AlertsWorkspace
        // for the rationale). HStack push-layout overflowed the
        // window at the 1180 minimum; ZStack lets the trace
        // inspector float over the rightmost ~340 pt of the graph
        // canvas. The slim "Show details" rail re-open affordance
        // gets the same overlay treatment so the canvas width stays
        // stable as the user toggles the inspector open/closed.
        ZStack(alignment: .topTrailing) {
            VStack(alignment: .leading, spacing: 16) {
                traceGraphExplainer
                tracePickerRow
                graphCanvas
            }
            .padding(16)
            .frame(maxWidth: .infinity, maxHeight: .infinity)

            if traceInspectorOpen, let trace = selectedTrace ?? traces.first {
                traceInspector(trace)
                    .shadow(color: Color.black.opacity(0.25), radius: 8, x: -4, y: 0)
                    .transition(V2Motion.inspectorSlide(reduceMotion: reduceMotion))
            } else if !traceInspectorOpen {
                showInspectorButton
                    .transition(V2Motion.inspectorSlide(reduceMotion: reduceMotion))
            }
        }
        .animation(V2Motion.inspectorPresent(reduceMotion: reduceMotion), value: traceInspectorOpen)
    }

    /// Brief explainer at the top of the TraceGraph tab. Pre-fix the
    /// tab opened straight into the picker + canvas with no context —
    /// users with no causal-graph background couldn't tell what a
    /// "trace" was, why the same node names recurred, or how this
    /// related to alerts. The card sits inside the regular v2 panel
    /// chrome so it blends with the picker / graph stack below.
    private var traceGraphExplainer: some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: "point.3.connected.trianglepath.dotted")
                .scaledSystem(16, weight: .semibold)
                .foregroundStyle(V2Theme.dataAccent)
                .padding(.top, 2)
            VStack(alignment: .leading, spacing: 4) {
                Text("What is a trace?")
                    .font(V2Theme.sectionTitle())
                    .foregroundStyle(V2Theme.primaryText)
                Text("A trace is the causal chain of process / file / network / persistence / AI-agent / TCC entities that participate in a high-severity event. The daemon anchors a trace when AnchorDetector decides an event is investigation-worthy (loader exec, persistence write, credential file access, etc.) and rolls forward every entity touched in the same lineage. Click any node for full identity + role; drag to rearrange; switch layout from the toolbar; right-click for copy / open-in-events shortcuts.")
                    .font(V2Theme.body())
                    .foregroundStyle(V2Theme.mutedText)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer()
        }
        .padding(14)
        .v2Panel()
    }

    /// Render a trace as a real hub-and-spoke graph (anchor at
    /// centre, other members radiating outward with edges drawn from
    /// the anchor). The "as list" toggle reveals an accessible text
    /// view of the same data for screen readers and dense traces.
    /// Loads via `traceMembers(traceId:)`. Falls back to a CLI hint
    /// when the provider returns empty (mock mode, no causalStore,
    /// or daemon hasn't materialised this trace yet).
    @ViewBuilder
    private func traceMembersList(_ trace: V2MockTrace) -> some View {
        let members = traceMembersCache[trace.id] ?? []
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 10) {
                Image(systemName: "point.3.connected.trianglepath.dotted")
                    .foregroundStyle(V2Theme.dataAccent)
                    .scaledSystem(16, weight: .semibold)
                Text(trace.title).font(V2Theme.sectionTitle()).foregroundStyle(V2Theme.primaryText)
                Spacer()
                V2StatusChip("\(members.count) entities", kind: .data)
                if !members.isEmpty {
                    Button {
                        graphAsList.toggle()
                    } label: {
                        HStack(spacing: 4) {
                            Image(systemName: graphAsList ? "point.3.connected.trianglepath.dotted" : "list.bullet")
                                .scaledSystem(10, weight: .semibold)
                            Text(graphAsList ? "Graph" : "List")
                                .scaledSystem(11, weight: .medium)
                        }
                        .foregroundStyle(V2Theme.mutedText)
                        .padding(.horizontal, 8).padding(.vertical, 4)
                        .background(V2Theme.panelBackground)
                        .overlay(RoundedRectangle(cornerRadius: 4)
                                    .stroke(V2Theme.panelBorder, lineWidth: 1))
                    }
                    .buttonStyle(.plain)
                    .help(graphAsList ? "Show as graph" : "Show as accessible list")
                }
            }
            if members.isEmpty {
                // Fallback: the trace has no resolvable members yet
                // (causal graph store missing, or the trace hasn't
                // materialised). Show a single CLI hint — not three.
                HStack(spacing: 8) {
                    Image(systemName: "terminal").foregroundStyle(V2Theme.mutedText)
                    Text("maccrabctl trace show \(trace.id)")
                        .font(V2Theme.mono()).foregroundStyle(V2Theme.primaryText)
                        .textSelection(.enabled)
                        .lineLimit(1)
                        .truncationMode(.middle)
                    Spacer()
                    V2ActionButton("Copy", icon: "doc.on.doc", style: .ghost) {
                        NSPasteboard.general.clearContents()
                        NSPasteboard.general.setString("maccrabctl trace show \(trace.id)", forType: .string)
                        state.showToast(V2Toast(kind: .success, title: "Command copied", detail: nil))
                    }
                }
                .padding(12)
                .background(V2Theme.panelBackground)
                .clipShape(RoundedRectangle(cornerRadius: V2Theme.smallCornerRadius))
                Text("Trace members couldn't be resolved from the causal graph store. Either the daemon hasn't materialised this trace yet, or the local tracegraph.db is empty.")
                    .font(V2Theme.meta())
                    .foregroundStyle(V2Theme.mutedText)
            } else if graphAsList {
                memberListView(members)
            } else {
                memberGraphView(members)
            }
        }
        .padding(16)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .v2Panel()
    }

    /// Accessible list view. Used when the user toggles "List" on the
    /// graph header, or could be wired to a VoiceOver fallback later.
    /// Each row carries the same click→popover and right-click context
    /// menu as the graph nodes so the list isn't a read-only fallback.
    @ViewBuilder
    private func memberListView(_ members: [V2TraceMember]) -> some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 4) {
                ForEach(members) { m in
                    let isSelected = selectedMemberId == m.id
                    HStack(spacing: 10) {
                        Image(systemName: m.isAnchor ? "flame.fill" : iconForEntityType(m.entityType))
                            .foregroundStyle(m.isAnchor ? V2Theme.high : V2Theme.dataAccent)
                            .scaledSystem(12, weight: m.isAnchor ? .bold : .regular)
                            .frame(width: 18, alignment: .center)
                        VStack(alignment: .leading, spacing: 1) {
                            Text(m.displayName)
                                .font(V2Theme.body())
                                .foregroundStyle(V2Theme.primaryText)
                                .lineLimit(1)
                                .truncationMode(.middle)
                            Text("\(m.entityType) · \(V2TimeFormat.relative(m.firstSeen))\(m.isAnchor ? " · anchor" : "")")
                                .font(V2Theme.meta())
                                .foregroundStyle(V2Theme.mutedText)
                        }
                        Spacer()
                        // v1.11.0 (audit UX MEDIUM): use .forward variant
                        // so the chevron mirrors under RTL locales
                        // (Arabic, Hebrew). The .right variant is
                        // direction-locked and looks broken in RTL.
                        Image(systemName: "chevron.forward")
                            .scaledSystem(9, weight: .semibold)
                            .foregroundStyle(V2Theme.mutedText)
                    }
                    .padding(.horizontal, 10)
                    .padding(.vertical, 6)
                    .background(
                        isSelected
                            ? V2Theme.brand.opacity(0.18)
                            : (m.isAnchor ? V2Theme.high.opacity(0.08) : V2Theme.panelBackground)
                    )
                    .clipShape(RoundedRectangle(cornerRadius: 6))
                    .contentShape(Rectangle())
                    .onTapGesture {
                        selectedMemberId = (selectedMemberId == m.id) ? nil : m.id
                    }
                    .contextMenu {
                        Button {
                            selectedMemberId = m.id
                        } label: { Label("Show details", systemImage: "info.circle") }
                        Button {
                            NSPasteboard.general.clearContents()
                            NSPasteboard.general.setString(m.displayName, forType: .string)
                            state.showToast(V2Toast(kind: .success, title: "Copied", detail: m.displayName))
                        } label: { Label("Copy label", systemImage: "doc.on.doc") }
                        Button {
                            NSPasteboard.general.clearContents()
                            NSPasteboard.general.setString(m.id, forType: .string)
                            state.showToast(V2Toast(kind: .success, title: "Copied entity ID", detail: m.id))
                        } label: { Label("Copy entity ID", systemImage: "number") }
                        Divider()
                        Button {
                            // Pre-fill the events FTS filter with the
                            // member's display name so the user lands
                            // on events for THIS entity, not the
                            // unfiltered firehose.
                            state.pendingEventsFilter = m.displayName
                            state.switchWorkspace(.events)
                        } label: { Label("Open in Events", systemImage: "list.bullet.rectangle") }
                    }
                    .popover(isPresented: Binding(
                        get: { selectedMemberId == m.id },
                        set: { if !$0 { selectedMemberId = nil } }
                    ), arrowEdge: .leading) {
                        memberDetailPopover(m).frame(width: 320)
                    }
                }
            }
        }
        .frame(maxHeight: .infinity)
    }

    /// Interactive graph view of the trace. Anchor renders centred /
    /// pinned per layout, non-anchor members radiate around it, edges
    /// drawn anchor→non-anchor (the only relation we can infer
    /// without `traceMembers` returning real edges). Per-node drag,
    /// pinch-zoom, and a 5-way layout switcher all live here. Drag a
    /// node and the layout flips to `.manual` so subsequent layout
    /// switches don't fight the user's positioning.
    @ViewBuilder
    private func memberGraphView(_ members: [V2TraceMember]) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            graphToolbar(members)
            GeometryReader { geo in
                // Cached layout: skip recomputing the force solver
                // unless an input changed.
                let key = "\(graphLayout.rawValue)|\(members.count)|\(Int(geo.size.width))|\(Int(geo.size.height))|\((selectedTrace ?? traces.first)?.id ?? "")"
                let basePositions: [String: CGPoint] = {
                    if cachedPositionKey == key && !cachedPositions.isEmpty {
                        return cachedPositions
                    }
                    let fresh = computePositions(layout: graphLayout, members: members, in: geo.size)
                    DispatchQueue.main.async {
                        cachedPositionKey = key
                        cachedPositions = fresh
                    }
                    return fresh
                }()
                let positions = mergeCustomPositions(basePositions)
                let anchor = members.first(where: { $0.isAnchor }) ?? members.first
                ZStack {
                    // Brand watermark — single oversized crab silhouette
                    // sitting behind everything. Hit-testing disabled
                    // so it doesn't intercept canvas / node clicks. Sized
                    // to ~78% of the smaller canvas dimension; opacity
                    // tuned low enough that it reads as paper texture
                    // rather than a competing element.
                    Text("🦀")
                        .scaledSystem(min(geo.size.width, geo.size.height) * 0.78)
                        .opacity(0.028)
                        .saturation(0.35)
                        .allowsHitTesting(false)
                        .accessibilityHidden(true)

                    // Background — clears selection on click
                    Color.clear
                        .contentShape(Rectangle())
                        .onTapGesture { selectedMemberId = nil }

                    // Scaled graph layer. Pinch / scroll-wheel zoom
                    // applies via .scaleEffect so the edges keep their
                    // crisp 1-pt rasterisation at any zoom level.
                    ZStack {
                        // Edges — observe the dragModel so lines
                        // follow the dragged node every frame, not
                        // just at drag-end. Pre-fix the Canvas read
                        // the static `positions` dict + ignored
                        // dragModel; lines visibly snapped to the new
                        // node position only after onEnded committed
                        // to customPositions.
                        if let anchor {
                            EdgeOverlay(
                                members: members,
                                positions: positions,
                                anchorId: anchor.id,
                                hoveredMemberId: hoveredMemberId,
                                zoom: graphZoom,
                                dragModel: dragModel
                            )
                            .allowsHitTesting(false)
                        }
                        // Nodes — each one is its own DraggableMemberNode
                        // child view that owns its in-flight drag offset
                        // as local @State. Pre-fix the parent owned a
                        // [String: CGSize] dragOffsets dict that mutated
                        // every frame of the drag, re-evaluating the
                        // entire traceGraphTab body (~8-15 ms / frame
                        // on traces >12 nodes). Now SwiftUI scopes the
                        // drag-frame redraw to a single node.
                        ForEach(members) { m in
                            if let p = positions[m.id] {
                                DraggableMemberNode(
                                    member: m,
                                    basePosition: p,
                                    zoom: graphZoom,
                                    isSelected: selectedMemberId == m.id,
                                    isHovered: hoveredMemberId == m.id,
                                    isDimmed: hoveredMemberId != nil
                                        && hoveredMemberId != m.id
                                        && !m.isAnchor,
                                    iconForType: iconForEntityType,
                                    onTap: {
                                        selectedMemberId = (selectedMemberId == m.id) ? nil : m.id
                                    },
                                    onHoverChanged: { hovering in
                                        hoveredMemberId = hovering ? m.id : (hoveredMemberId == m.id ? nil : hoveredMemberId)
                                    },
                                    onDragChange: { [dragModel] translation in
                                        // Push the in-flight offset
                                        // to the shared model. EdgeOverlay
                                        // observes and re-renders;
                                        // parent + other nodes do not.
                                        dragModel.offsets[m.id] = translation
                                    },
                                    onDragCommit: { delta in
                                        let final = CGPoint(
                                            x: p.x + delta.width,
                                            y: p.y + delta.height
                                        )
                                        customPositions[m.id] = final
                                        dragModel.offsets[m.id] = nil
                                        graphLayout = .manual
                                    },
                                    contextMenuContent: {
                                        AnyView(VStack {
                                            Button {
                                                selectedMemberId = m.id
                                            } label: { Label("Show details", systemImage: "info.circle") }
                                            Button {
                                                NSPasteboard.general.clearContents()
                                                NSPasteboard.general.setString(m.displayName, forType: .string)
                                                state.showToast(V2Toast(kind: .success, title: "Copied", detail: m.displayName))
                                            } label: { Label("Copy label", systemImage: "doc.on.doc") }
                                            Button {
                                                NSPasteboard.general.clearContents()
                                                NSPasteboard.general.setString(m.id, forType: .string)
                                                state.showToast(V2Toast(kind: .success, title: "Copied entity ID", detail: m.id))
                                            } label: { Label("Copy entity ID", systemImage: "number") }
                                            Divider()
                                            Button {
                                                state.pendingEventsFilter = m.displayName
                                                state.switchWorkspace(.events)
                                            } label: { Label("Open in Events", systemImage: "list.bullet.rectangle") }
                                        })
                                    },
                                    detailPopoverIsPresented: Binding(
                                        get: { selectedMemberId == m.id },
                                        set: { if !$0 { selectedMemberId = nil } }
                                    ),
                                    detailPopoverContent: {
                                        AnyView(memberDetailPopover(m))
                                    }
                                )
                            }
                        }
                    }
                    .scaleEffect(graphZoom, anchor: .center)
                    .gesture(
                        MagnificationGesture()
                            .onChanged { scale in
                                let newZoom = pinchBaseline * scale
                                graphZoom = min(max(newZoom, zoomMin), zoomMax)
                            }
                            .onEnded { _ in pinchBaseline = graphZoom }
                    )

                    // Bottom-right zoom controls.
                    VStack {
                        Spacer()
                        HStack {
                            Spacer()
                            zoomControls
                                .padding(8)
                        }
                    }
                    if members.count > 32 {
                        VStack {
                            Spacer()
                            HStack {
                                Text("\(members.count) entities — switch to List for full detail")
                                    .font(V2Theme.meta())
                                    .foregroundStyle(V2Theme.mutedText)
                                    .padding(.horizontal, 8).padding(.vertical, 4)
                                    .background(V2Theme.panelBackground.opacity(0.85))
                                    .clipShape(RoundedRectangle(cornerRadius: 4))
                                    .padding(8)
                                Spacer()
                            }
                        }
                    }
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
                .background(V2Theme.panelBackground.opacity(0.5))
                .clipShape(RoundedRectangle(cornerRadius: V2Theme.smallCornerRadius))
                .accessibilityElement(children: .contain)
                .accessibilityLabel("Trace graph with \(members.count) entities. Layout: \(graphLayout.label).")
            }
        }
        .frame(minHeight: 360, maxHeight: .infinity)
    }

    /// Layout segmented control + reset button.
    @ViewBuilder
    private func graphToolbar(_ members: [V2TraceMember]) -> some View {
        HStack(spacing: 8) {
            HStack(spacing: 2) {
                ForEach(V2TraceLayout.allCases) { layoutCase in
                    Button {
                        withAnimation(V2Motion.graphSpring(reduceMotion: reduceMotion)) {
                            // Switching to a non-manual layout discards
                            // custom positions so the chosen algorithm
                            // can take over.
                            if layoutCase != .manual {
                                customPositions.removeAll()
                            }
                            graphLayout = layoutCase
                        }
                    } label: {
                        HStack(spacing: 4) {
                            Image(systemName: layoutCase.icon)
                                .scaledSystem(10, weight: .semibold)
                            Text(layoutCase.label)
                                .scaledSystem(11, weight: .medium)
                        }
                        .foregroundStyle(graphLayout == layoutCase ? V2Theme.primaryText : V2Theme.mutedText)
                        .padding(.horizontal, 8).padding(.vertical, 4)
                        .background(graphLayout == layoutCase
                                    ? V2Theme.panelBackground
                                    : Color.clear)
                        .overlay(
                            RoundedRectangle(cornerRadius: 4)
                                .stroke(graphLayout == layoutCase
                                        ? V2Theme.panelBorder
                                        : .clear,
                                        lineWidth: 1)
                        )
                        .clipShape(RoundedRectangle(cornerRadius: 4))
                        .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                    .help(layoutCase.tooltip)
                }
            }
            Spacer()
            if !customPositions.isEmpty {
                Button {
                    withAnimation(V2Motion.graphSpring(reduceMotion: reduceMotion)) {
                        customPositions.removeAll()
                        dragModel.offsets.removeAll()
                        if graphLayout == .manual { graphLayout = .radial }
                    }
                } label: {
                    HStack(spacing: 4) {
                        Image(systemName: "arrow.counterclockwise")
                            .scaledSystem(10, weight: .semibold)
                        Text("Reset positions")
                            .scaledSystem(11, weight: .medium)
                    }
                    .foregroundStyle(V2Theme.mutedText)
                    .padding(.horizontal, 8).padding(.vertical, 4)
                    .background(V2Theme.panelBackground)
                    .overlay(RoundedRectangle(cornerRadius: 4)
                                .stroke(V2Theme.panelBorder, lineWidth: 1))
                    .clipShape(RoundedRectangle(cornerRadius: 4))
                }
                .buttonStyle(.plain)
                .help("Discard manual node positions and re-run the chosen layout")
            }
        }
    }

    /// Zoom in / out / reset cluster.
    @ViewBuilder
    private var zoomControls: some View {
        HStack(spacing: 2) {
            Button {
                graphZoom = max(zoomMin, graphZoom - 0.2)
                pinchBaseline = graphZoom
            } label: {
                Image(systemName: "minus.magnifyingglass")
                    .scaledSystem(11, weight: .semibold)
                    .frame(width: 22, height: 22)
                    .foregroundStyle(V2Theme.mutedText)
                    .background(V2Theme.panelBackground)
            }
            .buttonStyle(.plain)
            .help("Zoom out")
            .disabled(graphZoom <= zoomMin)

            Text("\(Int(graphZoom * 100))%")
                .scaledSystem(10, weight: .medium)
                .foregroundStyle(V2Theme.mutedText)
                .frame(width: 40)
                .padding(.vertical, 4)
                .background(V2Theme.panelBackground)
                .onTapGesture(count: 2) {
                    // Double-click reset to 100%
                    graphZoom = 1.0
                    pinchBaseline = 1.0
                }
                .help("Double-click to reset to 100%")

            Button {
                graphZoom = min(zoomMax, graphZoom + 0.2)
                pinchBaseline = graphZoom
            } label: {
                Image(systemName: "plus.magnifyingglass")
                    .scaledSystem(11, weight: .semibold)
                    .frame(width: 22, height: 22)
                    .foregroundStyle(V2Theme.mutedText)
                    .background(V2Theme.panelBackground)
            }
            .buttonStyle(.plain)
            .help("Zoom in")
            .disabled(graphZoom >= zoomMax)
        }
        .clipShape(RoundedRectangle(cornerRadius: 4))
        .overlay(RoundedRectangle(cornerRadius: 4).stroke(V2Theme.panelBorder, lineWidth: 1))
    }

    /// Merge per-node manual positions over a base layout. Manual
    /// positions take priority. The merged map is what gets rendered
    /// + drag-applied.
    private func mergeCustomPositions(_ base: [String: CGPoint]) -> [String: CGPoint] {
        guard !customPositions.isEmpty else { return base }
        var out = base
        for (id, p) in customPositions { out[id] = p }
        return out
    }

    /// Dispatch to the per-layout positioning function. Pure: no
    /// side-effects, deterministic for a given (layout, members,
    /// canvas-size) triple. The force layout uses a fixed-seed RNG so
    /// runs are stable across re-renders.
    private func computePositions(
        layout: V2TraceLayout, members: [V2TraceMember], in size: CGSize
    ) -> [String: CGPoint] {
        switch layout {
        case .manual, .radial:
            return radialPositions(members: members, in: size)
        case .hierarchical:
            return hierarchicalPositions(members: members, in: size)
        case .circular:
            return circularPositions(members: members, in: size)
        case .grid:
            return gridPositions(members: members, in: size)
        case .force:
            return forcePositions(members: members, in: size)
        }
    }

    /// Hierarchical: anchor at top, non-anchors evenly spread on a row
    /// below. With many nodes the row gets dense — caller may want
    /// circular or grid for >8.
    private func hierarchicalPositions(members: [V2TraceMember], in size: CGSize) -> [String: CGPoint] {
        var result: [String: CGPoint] = [:]
        guard !members.isEmpty, size.width > 0, size.height > 0 else { return result }
        let topY = max(60, size.height * 0.18)
        let bottomY = min(size.height - 50, size.height * 0.78)
        let anchor = members.first(where: { $0.isAnchor }) ?? members.first
        let nonAnchors = members.filter { $0.id != anchor?.id }
        if let anchor {
            result[anchor.id] = CGPoint(x: size.width / 2, y: topY)
        }
        if !nonAnchors.isEmpty {
            // Wrap into rows of at most 8 to keep the layout legible
            // for large traces.
            let rowSize = 8
            let rows = (nonAnchors.count + rowSize - 1) / rowSize
            let rowGap = (bottomY - topY - 70) / CGFloat(max(1, rows))
            for (idx, m) in nonAnchors.enumerated() {
                let row = idx / rowSize
                let col = idx % rowSize
                let cells = min(rowSize, nonAnchors.count - row * rowSize)
                let stepX = size.width / CGFloat(cells + 1)
                let x = stepX * CGFloat(col + 1)
                let y = topY + 70 + rowGap * (CGFloat(row) + 0.5)
                result[m.id] = CGPoint(x: x, y: y)
            }
        }
        return result
    }

    /// Circular: every member (anchor included) on the same ring.
    /// Anchor pinned to 12 o'clock so it's still visually distinguishable.
    private func circularPositions(members: [V2TraceMember], in size: CGSize) -> [String: CGPoint] {
        var result: [String: CGPoint] = [:]
        guard !members.isEmpty, size.width > 0, size.height > 0 else { return result }
        let centre = CGPoint(x: size.width / 2, y: size.height / 2)
        let radius = min(size.width, size.height) * 0.38
        let anchor = members.first(where: { $0.isAnchor }) ?? members.first
        var ordered: [V2TraceMember] = []
        if let anchor { ordered.append(anchor) }
        ordered.append(contentsOf: members.filter { $0.id != anchor?.id })
        let n = ordered.count
        guard n > 0 else { return result }
        let step = (.pi * 2.0) / Double(n)
        let phase = -Double.pi / 2.0
        for (i, m) in ordered.enumerated() {
            let theta = phase + Double(i) * step
            result[m.id] = CGPoint(
                x: centre.x + CGFloat(cos(theta)) * radius,
                y: centre.y + CGFloat(sin(theta)) * radius
            )
        }
        return result
    }

    /// Grid: simple uniform rows × cols. Works well for >12 entities
    /// where radial / circular get crowded.
    private func gridPositions(members: [V2TraceMember], in size: CGSize) -> [String: CGPoint] {
        var result: [String: CGPoint] = [:]
        guard !members.isEmpty, size.width > 0, size.height > 0 else { return result }
        let n = members.count
        let cols = max(1, Int((Double(n).squareRoot()).rounded(.up)))
        let rows = (n + cols - 1) / cols
        let cellW = size.width / CGFloat(cols + 1)
        let cellH = size.height / CGFloat(rows + 1)
        // Anchor first so it lands top-left for visual emphasis.
        let anchor = members.first(where: { $0.isAnchor }) ?? members.first
        var ordered: [V2TraceMember] = []
        if let anchor { ordered.append(anchor) }
        ordered.append(contentsOf: members.filter { $0.id != anchor?.id })
        for (idx, m) in ordered.enumerated() {
            let r = idx / cols
            let c = idx % cols
            result[m.id] = CGPoint(
                x: cellW * CGFloat(c + 1),
                y: cellH * CGFloat(r + 1)
            )
        }
        return result
    }

    /// Force-directed: 200 ticks of Fruchterman-Reingold-style spring
    /// + repulsion + slight pull-to-centre. Anchor pinned at the
    /// centre so the layout is visually anchored. Only edges we know
    /// are anchor→non-anchor; that produces a hub-and-spoke shape with
    /// node-pair repulsion preventing label overlap.
    private func forcePositions(members: [V2TraceMember], in size: CGSize) -> [String: CGPoint] {
        guard !members.isEmpty, size.width > 0, size.height > 0 else { return [:] }
        let centre = CGPoint(x: size.width / 2, y: size.height / 2)
        // Seed from radial so the iteration converges quickly and the
        // result is deterministic.
        var pos = radialPositions(members: members, in: size)
        let anchor = members.first(where: { $0.isAnchor }) ?? members.first
        let restLength: CGFloat = 110
        let damping: CGFloat = 0.82
        let iters = 200
        var vel: [String: CGSize] = [:]
        for m in members { vel[m.id] = .zero }

        for _ in 0..<iters {
            var force: [String: CGSize] = [:]
            for m in members { force[m.id] = .zero }

            // Repulsion: every pair pushes apart with 1/dist^2.
            for i in 0..<members.count {
                for j in (i+1)..<members.count {
                    let a = members[i].id
                    let b = members[j].id
                    guard let pa = pos[a], let pb = pos[b] else { continue }
                    let dx = pa.x - pb.x
                    let dy = pa.y - pb.y
                    let dist2 = max(dx*dx + dy*dy, 0.5)
                    let dist = dist2.squareRoot()
                    let mag = 6000 / dist2
                    let fx = (dx / dist) * mag
                    let fy = (dy / dist) * mag
                    force[a]?.width  += fx; force[a]?.height += fy
                    force[b]?.width  -= fx; force[b]?.height -= fy
                }
            }
            // Spring along anchor→non-anchor edges.
            if let anchor {
                guard let pa = pos[anchor.id] else { continue }
                for m in members where !m.isAnchor {
                    guard let pm = pos[m.id] else { continue }
                    let dx = pm.x - pa.x
                    let dy = pm.y - pa.y
                    let dist = max((dx*dx + dy*dy).squareRoot(), 0.5)
                    let displacement = dist - restLength
                    let mag = displacement * 0.05
                    force[m.id]?.width  -= (dx / dist) * mag
                    force[m.id]?.height -= (dy / dist) * mag
                    force[anchor.id]?.width  += (dx / dist) * mag
                    force[anchor.id]?.height += (dy / dist) * mag
                }
            }
            // Apply with damping. Pull all nodes weakly toward centre
            // so the cloud doesn't drift off-canvas.
            for m in members {
                let id = m.id
                guard var v = vel[id], let f = force[id], var p = pos[id] else { continue }
                v.width  = (v.width  + f.width  * 0.05) * damping
                v.height = (v.height + f.height * 0.05) * damping
                vel[id] = v
                if anchor?.id == id { continue }   // anchor pinned
                p.x += v.width
                p.y += v.height
                p.x += (centre.x - p.x) * 0.0015
                p.y += (centre.y - p.y) * 0.0015
                pos[id] = p
            }
        }
        // Anchor pinned at centre.
        if let anchor { pos[anchor.id] = centre }
        // Clamp inside canvas with a margin.
        let margin: CGFloat = 50
        for m in members {
            guard var p = pos[m.id] else { continue }
            p.x = min(max(p.x, margin), size.width  - margin)
            p.y = min(max(p.y, margin), size.height - margin)
            pos[m.id] = p
        }
        return pos
    }

    @ViewBuilder
    private func memberNode(_ m: V2TraceMember) -> some View {
        let isHover = hoveredMemberId == m.id
        let dim = hoveredMemberId != nil && !isHover && !m.isAnchor
        VStack(spacing: 4) {
            ZStack {
                Circle()
                    .fill(m.isAnchor ? V2Theme.high.opacity(0.18) : V2Theme.dataAccent.opacity(0.12))
                Circle()
                    .stroke(m.isAnchor ? V2Theme.high : V2Theme.dataAccent,
                            lineWidth: m.isAnchor ? 2 : 1)
                Image(systemName: m.isAnchor ? "flame.fill" : iconForEntityType(m.entityType))
                    .scaledSystem(m.isAnchor ? 14 : 11,
                                  weight: m.isAnchor ? .bold : .regular)
                    .foregroundStyle(m.isAnchor ? V2Theme.high : V2Theme.dataAccent)
            }
            .frame(width: m.isAnchor ? 36 : 26, height: m.isAnchor ? 36 : 26)
            .opacity(dim ? 0.35 : 1.0)
            Text(m.displayName)
                .scaledSystem(10, weight: m.isAnchor ? .semibold : .regular)
                .foregroundStyle(dim ? V2Theme.tertiaryText : V2Theme.primaryText)
                .lineLimit(1)
                .truncationMode(.middle)
                .frame(maxWidth: 90)
                .opacity(dim ? 0.5 : 1.0)
        }
        .padding(4)
        .background(
            (selectedMemberId == m.id ? V2Theme.brand.opacity(0.18) :
                (isHover ? V2Theme.brand.opacity(0.10) : Color.clear))
        )
        .clipShape(RoundedRectangle(cornerRadius: 6))
        .contentShape(Rectangle())
        .onHover { hovering in
            hoveredMemberId = hovering ? m.id : (hoveredMemberId == m.id ? nil : hoveredMemberId)
        }
        .onTapGesture {
            // Tap toggles the detail popover for this node. Tapping a
            // second time (or anywhere else) dismisses.
            selectedMemberId = (selectedMemberId == m.id) ? nil : m.id
        }
        .contextMenu {
            // Right-click / two-finger-click menu. Mirrors the actions
            // exposed in the popover so the user can avoid opening it
            // for quick operations like Copy.
            Button {
                selectedMemberId = m.id
            } label: { Label("Show details", systemImage: "info.circle") }
            Button {
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(m.displayName, forType: .string)
                copiedToast = true
                state.showToast(V2Toast(kind: .success, title: "Copied", detail: m.displayName))
            } label: { Label("Copy label", systemImage: "doc.on.doc") }
            Button {
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(m.id, forType: .string)
                state.showToast(V2Toast(kind: .success, title: "Copied entity ID", detail: m.id))
            } label: { Label("Copy entity ID", systemImage: "number") }
            Divider()
            Button {
                state.pendingEventsFilter = m.displayName
                state.switchWorkspace(.events)
            } label: { Label("Open in Events", systemImage: "list.bullet.rectangle") }
        }
        .popover(isPresented: Binding(
            get: { selectedMemberId == m.id },
            set: { if !$0 { selectedMemberId = nil } }
        ), arrowEdge: .leading) {
            memberDetailPopover(m).frame(width: 320)
        }
        .help("\(m.displayName)\n\(m.entityType) · first seen \(V2TimeFormat.relative(m.firstSeen))\(m.isAnchor ? " · anchor" : "")")
        .accessibilityLabel("\(m.isAnchor ? "Anchor: " : "")\(m.displayName), \(m.entityType)")
        .accessibilityHint("Click to show details. Right-click for actions.")
    }

    /// Detail popover shown when a node is clicked. Pre-rc12 had a much
    /// richer V2NodeDetailPopover with per-kind sections (process pid /
    /// cmdline / parent / code-sig, file sha256 / size / perms, network
    /// proto / endpoints / bytes, alert rule / mitre / evidence) backed
    /// by mock V2NodeDetails. Live TraceGraph members carry only the
    /// fields below — to restore the full per-kind detail we need
    /// `traceMembers(traceId:)` to return enriched payloads. Logged for
    /// rc14+ if the live causal store grows them.
    @ViewBuilder
    private func memberDetailPopover(_ m: V2TraceMember) -> some View {
        let kindColor = colorForEntityType(m.entityType)
        VStack(alignment: .leading, spacing: 12) {
            // Header
            HStack(spacing: 10) {
                ZStack {
                    Circle().fill(kindColor.opacity(0.18))
                    Image(systemName: m.isAnchor ? "flame.fill" : iconForEntityType(m.entityType))
                        .foregroundStyle(kindColor)
                        .scaledSystem(14, weight: .bold)
                }
                .frame(width: 32, height: 32)
                VStack(alignment: .leading, spacing: 2) {
                    Text(m.displayName)
                        .font(V2Theme.sectionTitle())
                        .foregroundStyle(V2Theme.primaryText)
                        .lineLimit(2)
                    HStack(spacing: 6) {
                        V2StatusChip(m.entityType, kind: .data,
                                     icon: iconForEntityType(m.entityType))
                        if m.isAnchor {
                            V2StatusChip("anchor", kind: .high, icon: "flame.fill")
                        }
                    }
                }
                Spacer()
                Button {
                    selectedMemberId = nil
                } label: {
                    Image(systemName: "xmark")
                        .scaledSystem(11, weight: .semibold)
                        .foregroundStyle(V2Theme.mutedText)
                        .frame(width: 22, height: 22)
                        .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .help("Close")
            }

            Divider()

            // Identity + timing
            VStack(alignment: .leading, spacing: 4) {
                detailRow(label: "Entity ID", value: m.id, mono: true, copyable: true)
                detailRow(label: "Type",      value: m.entityType, mono: true)
                detailRow(label: "First seen", value: V2TimeFormat.relative(m.firstSeen))
                detailRow(label: "Role",      value: m.isAnchor ? "Trace anchor" : "Member")
            }

            Divider()

            // Per-kind hint — explains what this entity type means in
            // the trace graph context. Same hint shown in the legend.
            HStack(alignment: .top, spacing: 6) {
                Image(systemName: "info.circle")
                    .foregroundStyle(V2Theme.mutedText)
                    .scaledSystem(11)
                Text(hintForEntityType(m.entityType))
                    .font(V2Theme.meta())
                    .foregroundStyle(V2Theme.mutedText)
                    .fixedSize(horizontal: false, vertical: true)
            }

            Divider()

            // Actions
            VStack(alignment: .leading, spacing: 6) {
                V2ActionButton("Copy label", icon: "doc.on.doc", style: .secondary) {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(m.displayName, forType: .string)
                    state.showToast(V2Toast(kind: .success, title: "Copied", detail: m.displayName))
                }
                V2ActionButton("Open in Events", icon: "list.bullet.rectangle", style: .secondary) {
                    state.pendingEventsFilter = m.displayName
                    state.switchWorkspace(.events)
                    selectedMemberId = nil
                }
            }
        }
        .padding(14)
        // Width set by callers (the graph overlay sets 320; the
        // list-mode popover that still uses .popover() sets it via
        // its own .frame). Don't lock width here — would conflict.
    }

    /// One key-value row inside the detail popover. The value is
    /// monospaced when it's an opaque ID/path, and gets a discreet
    /// copy-on-click affordance when `copyable` is true.
    @ViewBuilder
    private func detailRow(label: String, value: String, mono: Bool = false, copyable: Bool = false) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 8) {
            Text(label)
                .font(V2Theme.meta())
                .foregroundStyle(V2Theme.mutedText)
                .frame(width: 90, alignment: .leading)
            if copyable {
                Button {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(value, forType: .string)
                    state.showToast(V2Toast(kind: .success, title: "Copied", detail: value))
                } label: {
                    Text(value)
                        .font(mono ? V2Theme.mono() : V2Theme.body())
                        .foregroundStyle(V2Theme.primaryText)
                        .lineLimit(2)
                        .truncationMode(.middle)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
                .buttonStyle(.plain)
                .help("Click to copy")
            } else {
                Text(value)
                    .font(mono ? V2Theme.mono() : V2Theme.body())
                    .foregroundStyle(V2Theme.primaryText)
                    .lineLimit(2)
                    .truncationMode(.middle)
                    .textSelection(.enabled)
            }
        }
    }

    /// Tint colour by entity type — keeps node + chip + popover header
    /// visually consistent.
    private func colorForEntityType(_ type: String) -> Color {
        switch type.lowercased() {
        case "process":      return V2Theme.dataAccent
        case "file":         return V2Theme.medium
        case "network":      return V2Theme.aiAccent
        case "ai_agent":     return V2Theme.aiAccent
        case "persistence":  return V2Theme.high
        case "tcc":          return V2Theme.medium
        case "alert":        return V2Theme.critical
        default:             return V2Theme.dataAccent
        }
    }

    /// Short explanation per entity type. Surfaces in the popover so
    /// the user understands what a "process / file / persistence /
    /// ai_agent" node actually represents in the trace.
    private func hintForEntityType(_ type: String) -> String {
        switch type.lowercased() {
        case "process":     return "An OS process observed by the daemon. Captured via Endpoint Security NOTIFY_EXEC."
        case "file":        return "A file path the trace touched (open / write / rename). Hash + signing details available via the CLI."
        case "network":     return "A remote endpoint or DNS query observed in the trace's process subtree."
        case "ai_agent":    return "An AI coding-agent session (Claude Code, Cursor, Codex, etc.) attributed via lineage or W3C TRACEPARENT."
        case "persistence": return "A persistence mechanism (LaunchAgent, LaunchDaemon, login item, kernel extension)."
        case "tcc":         return "A privacy-permission grant or change observed during the trace."
        case "alert":       return "A detection rule that fired against an event in this trace."
        default:            return "An entity participating in the causal trace."
        }
    }

    /// Compute (anchor at centre, others on a ring) positions.
    /// For >12 non-anchor members, splits into two concentric rings
    /// to keep node spacing readable.
    private func radialPositions(members: [V2TraceMember], in size: CGSize) -> [String: CGPoint] {
        var result: [String: CGPoint] = [:]
        guard !members.isEmpty, size.width > 0, size.height > 0 else { return result }
        let centre = CGPoint(x: size.width / 2, y: size.height / 2)
        let anchor = members.first(where: { $0.isAnchor }) ?? members.first
        if let anchor {
            result[anchor.id] = centre
        }
        let nonAnchors = members.filter { $0.id != anchor?.id }
        guard !nonAnchors.isEmpty else { return result }
        // Ring sizes: 60% of min dimension for primary, 90% for outer.
        let minDim = min(size.width, size.height)
        let innerRadius = max(80, minDim * 0.30)
        let outerRadius = max(140, minDim * 0.42)
        let splitThreshold = 12
        let ringSplit = nonAnchors.count > splitThreshold
        let inner = ringSplit ? Array(nonAnchors.prefix(splitThreshold)) : nonAnchors
        let outer = ringSplit ? Array(nonAnchors.suffix(from: splitThreshold)) : []
        layoutRing(inner, radius: innerRadius, centre: centre, into: &result)
        if !outer.isEmpty {
            layoutRing(outer, radius: outerRadius, centre: centre, into: &result)
        }
        return result
    }

    private func layoutRing(_ items: [V2TraceMember],
                            radius: CGFloat,
                            centre: CGPoint,
                            into result: inout [String: CGPoint]) {
        guard !items.isEmpty else { return }
        let step = (.pi * 2.0) / Double(items.count)
        // Start from -90° (top) so the first node anchors visually.
        let phase = -Double.pi / 2.0
        for (i, m) in items.enumerated() {
            let theta = phase + Double(i) * step
            let x = centre.x + CGFloat(cos(theta)) * radius
            let y = centre.y + CGFloat(sin(theta)) * radius
            result[m.id] = CGPoint(x: x, y: y)
        }
    }

    private func iconForEntityType(_ type: String) -> String {
        switch type.lowercased() {
        case "process":      return "terminal"
        case "file":         return "doc.fill"
        case "network":      return "network"
        case "ai_agent":     return "wand.and.stars"
        case "persistence":  return "lock.fill"
        case "tcc":          return "hand.raised.fill"
        default:             return "circle.fill"
        }
    }

    /// Slim re-open affordance shown when the trace inspector is
    /// hidden. Click to bring it back.
    private var showInspectorButton: some View {
        VStack {
            Button {
                traceInspectorOpen = true
            } label: {
                VStack(spacing: 6) {
                    Image(systemName: "sidebar.right")
                        .scaledSystem(14, weight: .semibold)
                    Text("Show details")
                        .scaledSystem(10, weight: .semibold)
                        .rotationEffect(.degrees(-90))
                        .fixedSize()
                        .frame(width: 16, height: 88)
                }
                .foregroundStyle(V2Theme.mutedText)
                .padding(.vertical, 14)
                .padding(.horizontal, 6)
                .background(V2Theme.panelBackground)
                .overlay(
                    Rectangle().fill(V2Theme.panelBorder).frame(width: 1),
                    alignment: .leading
                )
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .help("Show trace inspector")
        }
    }

    private var tracePickerRow: some View {
        HStack(spacing: 12) {
            Text("Trace").font(V2Theme.cardTitle()).foregroundStyle(V2Theme.mutedText)
            tracePickerButton
            Text("\(currentTraceIndex + 1) of \(traces.count)")
                .font(V2Theme.meta())
                .foregroundStyle(V2Theme.tertiaryText)
                .monospacedDigit()
            HStack(spacing: 4) {
                navTraceButton(direction: -1, icon: "chevron.backward",  tooltip: "Previous trace  ⌥ ←")
                navTraceButton(direction: +1, icon: "chevron.forward", tooltip: "Next trace  ⌥ →")
            }
            Spacer()
            V2ActionButton("Export bundle", icon: "square.and.arrow.up", style: .secondary,
                           disabled: (selectedTrace ?? traces.first) == nil,
                           tooltip: "Export this trace as a signed .maccrabtrace bundle") {
                if let trace = selectedTrace ?? traces.first {
                    exportTrace(trace)
                }
            }
            V2ActionButton("Verify bundle…", icon: "checkmark.seal", style: .secondary,
                           tooltip: "Pick a previously-exported .maccrabtrace bundle to verify schema, Merkle root, and signature") {
                verifyBundle()
            }
        }
    }

    private var currentTraceIndex: Int {
        let id = (selectedTrace ?? traces.first)?.id
        return traces.firstIndex(where: { $0.id == id }) ?? 0
    }

    /// Compact dropdown button + popover list. Scales to any number
    /// of traces — popover is scrollable and gets a search field
    /// once there are more than 5 traces.
    private var tracePickerButton: some View {
        let current = selectedTrace ?? traces.first
        return Button {
            tracePickerOpen.toggle()
        } label: {
            HStack(spacing: 8) {
                if let trace = current {
                    Circle()
                        .fill(trace.severityHint.chipKind.color)
                        .frame(width: 8, height: 8)
                    if trace.isDemo {
                        V2StatusChip("DEMO", kind: .ai, icon: "theatermasks.fill")
                    }
                    Text(trace.title)
                        .scaledSystem(12, weight: .semibold)
                        .foregroundStyle(V2Theme.primaryText)
                        .lineLimit(1)
                        .frame(maxWidth: 280, alignment: .leading)
                } else {
                    Text("No trace").font(V2Theme.body()).foregroundStyle(V2Theme.mutedText)
                }
                Image(systemName: "chevron.down")
                    .scaledSystem(9, weight: .semibold)
                    .foregroundStyle(V2Theme.mutedText)
            }
            .padding(.horizontal, 10).padding(.vertical, 6)
            .background(V2Theme.panelBackground)
            .overlay(
                RoundedRectangle(cornerRadius: V2Theme.smallCornerRadius)
                    .stroke(V2Theme.panelBorder, lineWidth: 1)
            )
            .clipShape(RoundedRectangle(cornerRadius: V2Theme.smallCornerRadius))
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .help("Switch trace")
        .popover(isPresented: $tracePickerOpen, arrowEdge: .bottom) {
            tracePickerPopover
        }
    }

    /// Trace picker popover. Pre-fix this was a flat chronological
    /// list with a search field that only appeared past 5 traces — on
    /// any reasonably-active machine the list was a single homogeneous
    /// scroll and the user couldn't distinguish "the trace from this
    /// morning's incident" from "the ambient trace that fires when
    /// Spotlight reindexes". Now: search always visible, results
    /// grouped by recency (Active / Last 24h / Last 7d / Older), each
    /// row shows a severity dot + 2-line summary with node/edge
    /// counts and the root process more prominently.
    private var tracePickerPopover: some View {
        let q = tracePickerQuery.lowercased()
        let filtered = q.isEmpty
            ? traces
            : traces.filter {
                ($0.title + " " + $0.rootProcess + " " + $0.id)
                    .lowercased().contains(q)
            }
        let grouped = groupTracesByRecency(filtered)
        return VStack(spacing: 0) {
            // Header row with search + result count.
            HStack(spacing: 6) {
                Image(systemName: "magnifyingglass")
                    .foregroundStyle(V2Theme.mutedText)
                    .scaledSystem(11)
                TextField("Filter by title, process, or trace ID…", text: $tracePickerQuery)
                    .textFieldStyle(.plain)
                    .font(V2Theme.body())
                if !tracePickerQuery.isEmpty {
                    Button {
                        tracePickerQuery = ""
                    } label: {
                        Image(systemName: "xmark.circle.fill")
                            .scaledSystem(11)
                            .foregroundStyle(V2Theme.mutedText)
                    }
                    .buttonStyle(.plain)
                    .help("Clear filter")
                }
                Text("\(filtered.count) of \(traces.count)")
                    .font(V2Theme.meta())
                    .foregroundStyle(V2Theme.tertiaryText)
                    .monospacedDigit()
            }
            .padding(.horizontal, 12).padding(.vertical, 8)
            .background(V2Theme.panelBackground)
            Divider().background(V2Theme.panelBorder)

            ScrollView {
                LazyVStack(spacing: 0, pinnedViews: [.sectionHeaders]) {
                    if filtered.isEmpty {
                        Text(traces.isEmpty
                             ? "No traces yet — wait for the daemon to anchor one"
                             : "No traces match `\(tracePickerQuery)`")
                            .font(V2Theme.body())
                            .foregroundStyle(V2Theme.mutedText)
                            .padding(20)
                    } else {
                        ForEach(grouped, id: \.label) { group in
                            Section(header: tracePickerSectionHeader(group.label, count: group.traces.count)) {
                                ForEach(group.traces) { trace in
                                    tracePickerRow(trace)
                                }
                            }
                        }
                    }
                }
            }
            .frame(width: 460, height: 420)
        }
    }

    @ViewBuilder
    private func tracePickerSectionHeader(_ label: String, count: Int) -> some View {
        HStack(spacing: 6) {
            Text(label.uppercased())
                .scaledSystem(10, weight: .semibold)
                .foregroundStyle(V2Theme.tertiaryText)
                .tracking(0.5)
            Text("\(count)")
                .scaledSystem(10, weight: .medium)
                .foregroundStyle(V2Theme.mutedText)
                .padding(.horizontal, 5).padding(.vertical, 1)
                .background(V2Theme.panelBackground)
                .clipShape(Capsule())
            Spacer()
        }
        .padding(.horizontal, 12).padding(.top, 10).padding(.bottom, 4)
        .background(V2Theme.sidebarBackground.opacity(0.92))
    }

    @ViewBuilder
    private func tracePickerRow(_ trace: V2MockTrace) -> some View {
        let isOn = (selectedTrace ?? traces.first)?.id == trace.id
        Button {
            selectedTrace = trace
            traceInspectorOpen = true
            tracePickerOpen = false
        } label: {
            HStack(alignment: .top, spacing: 10) {
                // Severity dot. Anchor flame replaces the dot for
                // anchor-active traces (visually high-contrast).
                ZStack {
                    Circle()
                        .fill(trace.severityHint.chipKind.color.opacity(0.18))
                        .frame(width: 22, height: 22)
                    Circle()
                        .stroke(trace.severityHint.chipKind.color, lineWidth: 1.4)
                        .frame(width: 22, height: 22)
                    Image(systemName: "point.3.connected.trianglepath.dotted")
                        .scaledSystem(10, weight: .semibold)
                        .foregroundStyle(trace.severityHint.chipKind.color)
                }
                VStack(alignment: .leading, spacing: 2) {
                    HStack(spacing: 5) {
                        if trace.isDemo {
                            V2StatusChip("DEMO", kind: .ai)
                        }
                        Text(trace.title)
                            .scaledSystem(13, weight: isOn ? .semibold : .medium)
                            .foregroundStyle(V2Theme.primaryText)
                            .lineLimit(1)
                            .truncationMode(.middle)
                        Spacer()
                        V2StatusChip(trace.severityHint.label, kind: trace.severityHint.chipKind)
                    }
                    HStack(spacing: 6) {
                        Image(systemName: "terminal").scaledSystem(9)
                            .foregroundStyle(V2Theme.mutedText)
                        Text(trace.rootProcess)
                            .font(V2Theme.mono())
                            .foregroundStyle(V2Theme.neutral)
                            .lineLimit(1)
                            .truncationMode(.middle)
                    }
                    HStack(spacing: 8) {
                        // v1.11.0 (audit functionality MEDIUM): only render
                        // node/edge counts when populated. `toV2Trace`
                        // hardcodes both to 0 because the list view doesn't
                        // run a per-trace `loadTrace` round-trip — the
                        // detail view does. Until counts are persisted on
                        // the Trace row at materialization time, hide them
                        // rather than render a misleading "0n / 0e" badge.
                        if trace.nodeCount > 0 {
                            Label("\(trace.nodeCount)n", systemImage: "circle.dotted")
                                .font(V2Theme.meta())
                                .foregroundStyle(V2Theme.mutedText)
                        }
                        if trace.edgeCount > 0 {
                            Label("\(trace.edgeCount)e", systemImage: "arrow.up.right.circle")
                                .font(V2Theme.meta())
                                .foregroundStyle(V2Theme.mutedText)
                        }
                        if trace.nodeCount > 0 || trace.edgeCount > 0 {
                            Text("•").foregroundStyle(V2Theme.tertiaryText)
                        }
                        Text("updated \(V2TimeFormat.relative(trace.lastUpdated))")
                            .font(V2Theme.meta())
                            .foregroundStyle(V2Theme.mutedText)
                            .lineLimit(1)
                    }
                }
                if isOn {
                    Image(systemName: "checkmark.circle.fill")
                        .scaledSystem(14, weight: .semibold)
                        .foregroundStyle(V2Theme.brand)
                        .padding(.top, 2)
                }
            }
            .padding(.horizontal, 12).padding(.vertical, 8)
            .background(isOn ? V2Theme.brand.opacity(0.10) : Color.clear)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }

    /// Group traces by recency bucket. Anchor-active (lastUpdated <
    /// 1h) is the most useful for triage so it goes on top.
    private func groupTracesByRecency(_ traces: [V2MockTrace])
        -> [(label: String, traces: [V2MockTrace])]
    {
        let now = Date()
        var active: [V2MockTrace] = []
        var last24h: [V2MockTrace] = []
        var last7d: [V2MockTrace] = []
        var older: [V2MockTrace] = []
        for t in traces {
            let dt = now.timeIntervalSince(t.lastUpdated)
            if dt < 60 * 60 { active.append(t) }
            else if dt < 24 * 60 * 60 { last24h.append(t) }
            else if dt < 7 * 24 * 60 * 60 { last7d.append(t) }
            else { older.append(t) }
        }
        // Sort within each group: severity desc, then recency desc.
        let sortKey: (V2MockTrace) -> (Int, TimeInterval) = {
            ($0.severityHint.sortOrder, -$0.lastUpdated.timeIntervalSince1970)
        }
        var out: [(String, [V2MockTrace])] = []
        if !active.isEmpty   { out.append(("Active (last hour)",  active.sorted   { sortKey($0) < sortKey($1) })) }
        if !last24h.isEmpty  { out.append(("Last 24 hours",       last24h.sorted  { sortKey($0) < sortKey($1) })) }
        if !last7d.isEmpty   { out.append(("Last 7 days",         last7d.sorted   { sortKey($0) < sortKey($1) })) }
        if !older.isEmpty    { out.append(("Older",               older.sorted    { sortKey($0) < sortKey($1) })) }
        return out
    }

    private func navTraceButton(direction: Int, icon: String, tooltip: String) -> some View {
        Button {
            let target = currentTraceIndex + direction
            guard target >= 0, target < traces.count else { return }
            selectedTrace = traces[target]
            traceInspectorOpen = true
        } label: {
            Image(systemName: icon)
                .scaledSystem(10, weight: .semibold)
                .foregroundStyle(V2Theme.mutedText)
                .frame(width: 22, height: 22)
                .background(V2Theme.hoverBackground)
                .clipShape(RoundedRectangle(cornerRadius: 4))
                .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .disabled(direction < 0 ? currentTraceIndex == 0 : currentTraceIndex >= traces.count - 1)
        .help(tooltip)
    }

    @ViewBuilder
    private var graphCanvas: some View {
        if let trace = selectedTrace ?? traces.first {
            traceMembersList(trace)
                .task(id: trace.id) {
                    if traceMembersCache[trace.id] == nil {
                        let members = await state.provider.traceMembers(traceId: trace.id)
                        await MainActor.run {
                            traceMembersCache[trace.id] = members
                        }
                    }
                }
        } else {
            // B7: an empty trace list can mean two very different things —
            // a healthy-but-quiet machine (nothing worth anchoring yet), or
            // a daemon that isn't reporting at all. Pre-fix both rendered
            // the identical "No traces materialized yet" copy, so for a
            // detection tool the dangerous case (engine blind) looked exactly
            // like the safe one. Gate on the engine heartbeat we already
            // fetch in reload(): stale (>120s) or absent → say so explicitly.
            let daemonReporting = engineHeartbeat.map { !$0.isStale } ?? false
            VStack(alignment: .leading, spacing: 16) {
                V2EmptyState(
                    title: daemonReporting
                        ? "No traces materialized yet"
                        : "Daemon not reporting — traces unavailable",
                    body: daemonReporting
                        ? "MacCrab anchors a trace when a high-severity pattern fires (loader exec, persistence write, credential read, etc.). When the daemon's trace materializer runs, the most-recent matching events appear here as a causal graph."
                        : "The detection engine hasn't sent a heartbeat in over two minutes, so the trace graph can't be shown and an empty list here does NOT mean the machine is clean. Check the daemon / System Extension status in the System workspace.",
                    icon: daemonReporting
                        ? "point.3.connected.trianglepath.dotted"
                        : "exclamationmark.triangle"
                )
                .v2Panel()

                if !recentAlerts.isEmpty {
                    VStack(alignment: .leading, spacing: 8) {
                        HStack {
                            Text("Recent high-severity alerts")
                                .font(V2Theme.sectionTitle())
                                .foregroundStyle(V2Theme.primaryText)
                            Spacer()
                            Text("Likely candidates for trace anchoring")
                                .font(V2Theme.meta())
                                .foregroundStyle(V2Theme.mutedText)
                        }
                        ForEach(recentAlerts) { alert in
                            Button {
                                state.goto(V2NavigationDestination(
                                    workspace: .alerts, tab: .alertsOpen, entityId: alert.id
                                ))
                            } label: {
                                HStack(spacing: 10) {
                                    V2SeverityDot(alert.severity.chipKind)
                                    VStack(alignment: .leading, spacing: 1) {
                                        Text(alert.title)
                                            .font(V2Theme.body())
                                            .foregroundStyle(V2Theme.primaryText)
                                            .lineLimit(1)
                                        Text("\(alert.process) · \(alert.ruleId) · \(V2TimeFormat.relative(alert.timestamp))")
                                            .font(V2Theme.meta())
                                            .foregroundStyle(V2Theme.mutedText)
                                            .lineLimit(1)
                                    }
                                    Spacer()
                                    Image(systemName: "arrow.up.forward")
                                        .scaledSystem(10)
                                        .foregroundStyle(V2Theme.mutedText)
                                }
                                .padding(10)
                                .background(V2Theme.panelBackground)
                                .clipShape(RoundedRectangle(cornerRadius: V2Theme.smallCornerRadius))
                                .contentShape(Rectangle())
                            }
                            .buttonStyle(.plain)
                        }
                    }
                    .v2Panel()
                }
                Spacer()
            }
            .padding(20)
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        }
    }

    @ViewBuilder
    private func traceInspector(_ trace: V2MockTrace) -> some View {
        V2Inspector(title: trace.title,
                    subtitle: trace.rootProcess,
                    onClose: {
                        // X button hides the inspector entirely.
                        // Re-open via the trace picker or the slim
                        // "Show details" rail.
                        traceInspectorOpen = false
                    }) {
            if trace.isDemo {
                HStack {
                    V2StatusChip("DEMO TRACE", kind: .ai, icon: "theatermasks.fill")
                    Spacer()
                }
            }
            HStack(spacing: 8) {
                V2StatusChip(trace.severityHint.label, kind: trace.severityHint.chipKind)
                // v1.11.0 (audit functionality MEDIUM): same gate as the
                // list view above — only render counts when actually
                // populated to avoid misleading "0 nodes / 0 edges" chips.
                if trace.nodeCount > 0 {
                    V2StatusChip("\(trace.nodeCount) nodes", kind: .neutral)
                }
                if trace.edgeCount > 0 {
                    V2StatusChip("\(trace.edgeCount) edges", kind: .neutral)
                }
            }
            V2InspectorSection(String(localized: "inspector.anchorVerdict", defaultValue: "Anchor verdict")) {
                Text(trace.anchorVerdict)
                    .font(V2Theme.body())
                    .foregroundStyle(V2Theme.primaryText)
            }
            V2InspectorSection(String(localized: "inspector.timeline", defaultValue: "Timeline")) {
                V2InspectorKeyValue("First seen", V2TimeFormat.relative(trace.firstSeen))
                V2InspectorKeyValue("Last update", V2TimeFormat.relative(trace.lastUpdated))
            }
            V2InspectorSection(String(localized: "inspector.criticalPath", defaultValue: "Critical path")) {
                ForEach(trace.rootProcess.split(separator: "→").map { $0.trimmingCharacters(in: .whitespaces) },
                        id: \.self) { step in
                    HStack(spacing: 6) {
                        Image(systemName: "circle.fill")
                            .foregroundStyle(V2Theme.dataAccent)
                            .scaledSystem(6)
                        Text(step).font(V2Theme.mono()).foregroundStyle(V2Theme.primaryText)
                    }
                }
            }
            V2InspectorSection(String(localized: "inspector.actions", defaultValue: "Actions")) {
                V2ActionButton("Open Agent Traces", icon: "wand.and.stars", style: .secondary) {
                    state.selectTab(.investigationAgentTraces)
                }
                V2ActionButton("Run AI analysis", icon: "brain.head.profile", style: .secondary) {
                    state.selectTab(.investigationAIAnalysis)
                }
                V2ActionButton("View as events", icon: "list.bullet", style: .secondary) {
                    state.pendingEventsFilter = trace.rootProcess
                    // Centre the events query on the trace's window:
                    // since first-seen (anchor time), until last-
                    // updated. Pad by 5 min on either side so events
                    // immediately before/after the trace's
                    // observation window are also visible.
                    let centre = Date(timeIntervalSince1970:
                        (trace.firstSeen.timeIntervalSince1970
                         + trace.lastUpdated.timeIntervalSince1970) / 2)
                    let halfWindow = max(
                        15 * 60,
                        trace.lastUpdated.timeIntervalSince(trace.firstSeen) / 2 + 5 * 60
                    )
                    state.pendingEventsCenterTime = centre
                    state.pendingEventsHalfWindowSeconds = halfWindow
                    state.switchWorkspace(.events)
                }
            }
        }
    }

    // MARK: - Agent Traces

    /// Agent Traces tab — wraps the v1 AgentTracesView (search, list,
    /// detail pane with span timeline + attribution stats + receiver
    /// toggle). Pre-fix this was a static V2EmptyState that didn't
    /// surface the real state of the OTLP receiver or the recent
    /// trace count, so users couldn't tell whether the feature was
    /// off, broken, or just quiet.
    private var agentTracesTab: some View {
        VStack(spacing: 0) {
            agentTracesExplainer
            AgentTracesView(appState: appState)
                .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
    }

    /// Brief explainer above the wrapped v1 AgentTracesView. Same
    /// shape as `traceGraphExplainer` so the two investigation tabs
    /// have matching openings; gives the user enough context to tell
    /// "this is W3C OTel correlation" from "the causal trace
    /// renderer is broken".
    private var agentTracesExplainer: some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: "wand.and.stars")
                .scaledSystem(16, weight: .semibold)
                .foregroundStyle(V2Theme.aiAccent)
                .padding(.top, 2)
            VStack(alignment: .leading, spacing: 4) {
                Text("What appears here?")
                    .font(V2Theme.sectionTitle())
                    .foregroundStyle(V2Theme.primaryText)
                Text("Agent Traces are W3C TRACEPARENT spans MacCrab ingested over its loopback OTLP receiver from AI coding tools (Claude Code, Cursor, Codex, Continue, Windsurf). Each row is one trace = one model-call lineage; expanding shows span timing + tool calls + the causal-graph events that fired during the span. Empty until you enable the receiver below and an OTel-emitting tool runs against it.")
                    .font(V2Theme.body())
                    .foregroundStyle(V2Theme.mutedText)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer()
        }
        .padding(14)
        .v2Panel()
        .padding([.horizontal, .top], 16)
    }

    // MARK: - AI Analysis

    private var aiAnalysisTab: some View {
        // v1.18: surface the ENGINE's actual LLM health (from the heartbeat
        // llm block). Campaign investigations run in the detection engine,
        // not the app — Settings → AI Backend now pushes config to the
        // engine. Showing real engine reachability stops "enabled but
        // unreachable" from being invisible and stops pointing the operator
        // at a control that doesn't reflect engine state.
        let engineLLM = engineHeartbeat?.llm
        return VStack(alignment: .leading, spacing: 16) {
            V2EmptyState(
                title: "No AI investigation summary yet",
                body: "MacCrab generates an LLM investigation when a campaign is detected at HIGH or CRITICAL severity. The detection engine runs it using its own backend — Settings → AI Backend pushes your configuration to the engine (Ollama local is recommended). Trigger a campaign or open an alert detail to see analysis here.",
                icon: "brain.head.profile"
            )
            .v2Panel()
            if let llm = engineLLM {
                Label("Engine LLM: \(llm.summary)",
                      systemImage: llm.healthy ? "checkmark.seal"
                        : (llm.configured ? "exclamationmark.triangle" : "minus.circle"))
                    .font(.caption)
                    .foregroundColor(llm.healthy ? .secondary
                        : (llm.configured ? .orange : .secondary))
                    .padding(.horizontal, 4)
            }
            Spacer()
        }
        .padding(16)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
    }

    // MARK: - Forensics moved banner (v1.17)

}

// MARK: - V2TraceLayout

/// Layout algorithms for the trace graph. Switching between them
/// keeps the same data; only the (x, y) per node changes. The
/// `.manual` case represents "user has dragged at least one node and
/// pinned it" — subsequent layout switches don't disturb pinned
/// positions.
public enum V2TraceLayout: String, CaseIterable, Identifiable {
    case radial
    case hierarchical
    case circular
    case grid
    case force
    case manual

    public var id: String { rawValue }

    public var label: String {
        switch self {
        case .radial:        return "Radial"
        case .hierarchical:  return "Hierarchical"
        case .circular:      return "Circular"
        case .grid:          return "Grid"
        case .force:         return "Force"
        case .manual:        return "Manual"
        }
    }

    public var icon: String {
        switch self {
        case .radial:        return "circle.dotted"
        case .hierarchical:  return "rectangle.stack"
        case .circular:      return "circle"
        case .grid:          return "square.grid.3x3"
        case .force:         return "atom"
        case .manual:        return "hand.draw"
        }
    }

    public var tooltip: String {
        switch self {
        case .radial:        return "Anchor centred, members on a ring"
        case .hierarchical:  return "Anchor at top, members below in rows"
        case .circular:      return "All entities on a single ring"
        case .grid:          return "Uniform rows × columns"
        case .force:         return "Force-directed (spring + repulsion)"
        case .manual:        return "Custom positions from your drags"
        }
    }
}

// MARK: - DraggableMemberNode

/// Per-node child view that owns its in-flight drag offset as local
/// `@State`. Pre-fix the parent V2InvestigationWorkspace held a
/// `[String: CGSize] dragOffsets` dictionary that mutated on every
/// drag frame (~60 Hz). Each mutation re-evaluated the entire
/// traceGraphTab body — picker, toolbar, every node's body, the
/// canvas, the inspector — for ~8-15 ms / frame on traces with >12
/// nodes. By moving the offset down here, SwiftUI scopes the
/// drag-frame redraw to a single node + its parent's `.position()`
/// modifier, which is what we want.
private struct DraggableMemberNode: View {
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    let member: V2TraceMember
    let basePosition: CGPoint
    let zoom: CGFloat
    let isSelected: Bool
    let isHovered: Bool
    let isDimmed: Bool
    let iconForType: (String) -> String
    let onTap: () -> Void
    let onHoverChanged: (Bool) -> Void
    /// Called every frame during drag with the live (zoomed)
    /// translation. Wired to DragPositionsModel.offsets so the
    /// EdgeOverlay can redraw lines that track the moving node.
    /// Default no-op for callers that don't care.
    var onDragChange: (CGSize) -> Void = { _ in }
    /// Called once at drag-end with the unscaled total delta.
    let onDragCommit: (CGSize) -> Void
    let contextMenuContent: () -> AnyView
    @Binding var detailPopoverIsPresented: Bool
    let detailPopoverContent: () -> AnyView

    @State private var dragTranslation: CGSize = .zero

    var body: some View {
        let m = member
        let dim = isDimmed
        // Visual chrome — kept tight to the node's natural size so
        // overlays/popovers attach to the node, not the parent
        // container. Pre-fix the .overlay was applied AFTER the
        // .position modifier; SwiftUI's .position wraps the view in a
        // PARENT-SIZED layout container and centers the modified view
        // at the given point. .overlay(.topLeading) then aligns to
        // that parent-sized container's top-left — the workspace's
        // corner — instead of the node. Worse, the position-modified
        // view's hit-test region is the whole parent, so once one
        // node had .zIndex(999) it captured every click in the
        // workspace and no other node could be selected. The fix is
        // to apply .overlay BEFORE .position, so the overlay anchors
        // to the node's intrinsic frame and the position modifier
        // wraps the (node + card) as a unit.
        let nodeBody = VStack(spacing: 4) {
            ZStack {
                Circle()
                    .fill(m.isAnchor ? V2Theme.high.opacity(0.18) : V2Theme.dataAccent.opacity(0.12))
                Circle()
                    .stroke(m.isAnchor ? V2Theme.high : V2Theme.dataAccent,
                            lineWidth: m.isAnchor ? 2 : 1)
                Image(systemName: m.isAnchor ? "flame.fill" : iconForType(m.entityType))
                    .scaledSystem(m.isAnchor ? 14 : 11,
                                  weight: m.isAnchor ? .bold : .regular)
                    .foregroundStyle(m.isAnchor ? V2Theme.high : V2Theme.dataAccent)
            }
            .frame(width: m.isAnchor ? 36 : 26, height: m.isAnchor ? 36 : 26)
            .opacity(dim ? 0.35 : 1.0)
            Text(m.displayName)
                .scaledSystem(10, weight: m.isAnchor ? .semibold : .regular)
                .foregroundStyle(dim ? V2Theme.tertiaryText : V2Theme.primaryText)
                .lineLimit(1)
                .truncationMode(.middle)
                .frame(maxWidth: 90)
                .opacity(dim ? 0.5 : 1.0)
        }
        .padding(4)
        .background(
            isSelected
                ? V2Theme.brand.opacity(0.18)
                : (isHovered ? V2Theme.brand.opacity(0.10) : Color.clear)
        )
        .clipShape(RoundedRectangle(cornerRadius: 6))
        .contentShape(Rectangle())
        .onHover { onHoverChanged($0) }
        .onTapGesture { onTap() }
        // Use `.global` coordinate space so translation is reported
        // in window coords. With the default `.local` space, the
        // origin tracks the modified view — and since we MOVE the
        // view via `.position()` based on dragTranslation, the
        // gesture's reference origin shifts every frame, causing
        // translation values to oscillate / jitter / "mirror" the
        // motion. Window-anchored translation is stable: the cursor
        // moved 100 visible px regardless of where the node ended up.
        // Then divide by zoom to convert window-px to unscaled-graph
        // coordinates so .position() math is unchanged.
        .gesture(
            DragGesture(minimumDistance: 3, coordinateSpace: .global)
                .onChanged { value in
                    dragTranslation = value.translation
                    onDragChange(value.translation)
                }
                .onEnded { value in
                    let unscaled = CGSize(
                        width: value.translation.width / max(zoom, 0.1),
                        height: value.translation.height / max(zoom, 0.1)
                    )
                    dragTranslation = .zero
                    onDragCommit(unscaled)
                }
        )
        .contextMenu { contextMenuContent() }

        return nodeBody
            // Detail card — anchored to the node's natural frame so
            // the card sits next to the node rather than at the
            // workspace corner. Hidden during drag (`dragTranslation
            // == .zero`) so the 320pt card with shadow + clipShape +
            // counter-scale doesn't rasterize at 60 Hz alongside the
            // moving node — that was the source of the drag jitter.
            // The card reappears at the node's new resting position
            // when the user releases the drag.
            //
            // Offset: ≥ 110pt to clear the longest possible label
            // (label uses `.frame(maxWidth: 90)` + 4pt padding both
            // sides of the VStack). The icon ZStack is 26-36pt; what
            // dominates the node's intrinsic width is the label, so
            // a single offset value clears both anchor + regular
            // members. .fixedSize keeps the card at 320pt regardless
            // of the node's tiny frame.
            .overlay(alignment: .topLeading) {
                if detailPopoverIsPresented && dragTranslation == .zero {
                    detailPopoverContent()
                        .frame(width: 320)
                        .fixedSize(horizontal: true, vertical: false)
                        // Pre-fix the card used V2Theme.panelBackground
                        // which is 0.038 alpha — barely visible over
                        // other nodes / edges. Stack a system
                        // windowBackground (opaque) UNDER the panel
                        // tint so the card sits clearly above the
                        // graph regardless of what's behind it.
                        .background(Color(NSColor.windowBackgroundColor))
                        .background(V2Theme.panelBackground)
                        .overlay(
                            RoundedRectangle(cornerRadius: V2Theme.smallCornerRadius)
                                .stroke(V2Theme.panelBorder, lineWidth: 1)
                        )
                        .clipShape(RoundedRectangle(cornerRadius: V2Theme.smallCornerRadius))
                        .shadow(color: .black.opacity(0.32), radius: 16, y: 6)
                        .scaleEffect(1.0 / max(zoom, 0.1), anchor: .topLeading)
                        .offset(x: 110, y: -8)
                        .allowsHitTesting(true)
                        .transition(V2Motion.nodeReveal(reduceMotion: reduceMotion))
                        .zIndex(999)
                }
            }
            .position(
                x: basePosition.x + dragTranslation.width / max(zoom, 0.1),
                y: basePosition.y + dragTranslation.height / max(zoom, 0.1)
            )
            // Disable implicit animations on the drag-translation
            // axis. SwiftUI inherits the parent's animation context
            // (the V2Motion.navigation spring on workspace switch +
            // the layout-switcher spring on graphLayout change). Both
            // have the right motion semantics for their own values,
            // but they were leaking onto every body re-eval — every
            // drag frame fed dragTranslation through a spring
            // interpolator at ~0.4s response, which read as visible
            // jitter as the spring chased the cursor instead of
            // tracking it directly.
            .animation(nil, value: dragTranslation)
            .help("\(m.displayName)\n\(m.entityType) · first seen \(V2TimeFormat.relative(m.firstSeen))\(m.isAnchor ? " · anchor" : "")")
            .accessibilityLabel("\(m.isAnchor ? "Anchor: " : "")\(m.displayName), \(m.entityType)")
            .accessibilityHint("Click to show details. Right-click for actions. Drag to reposition.")
    }
}

// MARK: - DragPositionsModel + EdgeOverlay

/// Shared mutable model for in-flight per-node drag offsets. Lives
/// as `@State private var dragModel = DragPositionsModel()` on the
/// parent V2InvestigationWorkspace — that means the parent owns it
/// but DOES NOT observe its @Published changes (no @StateObject /
/// @ObservedObject). Only views that explicitly take it via
/// `@ObservedObject` (just EdgeOverlay below) re-render when offsets
/// change. DraggableMemberNode writes to it via callback without
/// observing, so the parent + non-dragged nodes stay quiet at 60Hz.
@MainActor
final class DragPositionsModel: ObservableObject {
    @Published var offsets: [String: CGSize] = [:]
}

/// Edge canvas overlay. Observes DragPositionsModel so each frame of
/// a drag, the lines redraw to track the moving node. Pre-fix the
/// parent V2InvestigationWorkspace had a Canvas inline that read the
/// static `positions` dict — lines snapped only at drag-end (when
/// `customPositions` finally committed).
private struct EdgeOverlay: View {
    let members: [V2TraceMember]
    let positions: [String: CGPoint]
    let anchorId: String
    let hoveredMemberId: String?
    let zoom: CGFloat
    @ObservedObject var dragModel: DragPositionsModel

    var body: some View {
        Canvas { ctx, _ in
            guard let from = livePos(for: anchorId) else { return }
            for m in members where !m.isAnchor {
                guard let to = livePos(for: m.id) else { continue }
                var path = Path()
                path.move(to: from)
                path.addLine(to: to)
                let dim = (hoveredMemberId != nil && hoveredMemberId != m.id)
                ctx.stroke(
                    path,
                    with: .color(dim
                        ? V2Theme.panelBorder.opacity(0.4)
                        : V2Theme.dataAccent.opacity(0.55)),
                    style: StrokeStyle(
                        lineWidth: (dim ? 1 : 1.5) / max(zoom, 0.5),
                        lineCap: .round
                    )
                )
            }
        }
    }

    /// Returns the visual position of a node, accounting for any
    /// in-flight drag offset. Drag offsets are stored in the shared
    /// model in raw (zoomed) coordinates so we divide by `zoom` to
    /// match the unscaled position space the layout engines use.
    private func livePos(for id: String) -> CGPoint? {
        guard let base = positions[id] else { return nil }
        let off = dragModel.offsets[id] ?? .zero
        return CGPoint(
            x: base.x + off.width / max(zoom, 0.1),
            y: base.y + off.height / max(zoom, 0.1)
        )
    }
}

