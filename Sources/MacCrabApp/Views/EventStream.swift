// EventStream.swift
// MacCrabApp
//
// Live event stream viewer (similar to ProcMon) showing security events
// in a scrollable table with category filtering and pause controls.

import SwiftUI
import MacCrabCore

// MARK: - EventStream

enum TimeRange: String, CaseIterable {
    case lastHour = "Last Hour"
    case last24h = "Last 24 Hours"
    case last7d = "Last 7 Days"
    case all = "All Time"

    var seconds: TimeInterval? {
        switch self {
        case .lastHour: return 3600
        case .last24h: return 86400
        case .last7d: return 604800
        case .all: return nil
        }
    }
}

struct EventStream: View {
    @ObservedObject var appState: AppState
    @State private var filterText: String = ""
    @State private var filterCategory: EventCategory? = nil
    @State private var isPaused: Bool = false
    @State private var autoScroll: Bool = true
    @State private var selectedEventID: EventViewModel.ID? = nil
    @State private var timeRange: TimeRange = .all
    @State private var sortOrder = [KeyPathComparator(\EventViewModel.timestamp, order: .reverse)]
    @Environment(\.accessibilityReduceMotion) var reduceMotion

    /// v1.7.11: memoized cache. Pre-fix this was a computed `var
    /// filteredCache: [EventViewModel]` that re-filtered AND re-sorted
    /// `appState.events` on every body re-evaluation, AND was read TWICE
    /// per body call (count badge + Table data). Combined with macOS
    /// `Table`'s NSTableView backing — which inflates Auto Layout
    /// constraints on every rebind and doesn't release them until the
    /// view is dismantled — this drove a 333-constraint/sec leak.
    /// Field-reproduced: 5 min on Events tab added 100K NSLayoutConstraint
    /// instances. With the dashboard parked on Events all day, total
    /// retained constraints reached 1+ million / ~500 MB RSS.
    ///
    /// Fix: hold the filtered+sorted result in @State and only recompute
    /// when an actual input changes (events list, filter category, filter
    /// text, time range, sort order). SwiftUI sees a stable array
    /// reference between unrelated AppState mutations (heartbeat,
    /// agentLineage, mcpBaselines, etc.) and stops re-binding the Table.
    @State private var filteredCache: [EventViewModel] = []
    /// v1.8.0: warm-tier aggregate rows surfaced when `timeRange` exceeds the
    /// 24h hot-tier window. Empty inside the window — the live filteredCache
    /// covers that path. Backed by `event_aggregates` rolled up by the daemon's
    /// 6-hourly sweep; only summary fields (no per-event detail).
    @State private var aggregateRows: [EventStore.AggregateRow] = []
    /// True when the current `timeRange` selection looks past the 24h hot
    /// tier. Drives the "summarized — drill in for detail" banner + table swap.
    private var isAggregateMode: Bool {
        guard let seconds = timeRange.seconds else { return true }   // .all
        return seconds > 86400
    }

    /// Number of days back to ask the warm tier for. `.all` clamps to 30
    /// since that's the aggregate retention window.
    private var rangeDays: Int {
        guard let seconds = timeRange.seconds else { return 30 }
        return max(1, Int(seconds / 86400))
    }

    /// Composite key forcing the .task(id:) to re-run on either input change.
    private var aggregateInputsKey: String {
        "\(timeRange.rawValue)|\(filterCategory?.rawValue ?? "all")"
    }

    /// ISO date string for `daysAgo` days before now. Matches the
    /// `strftime('%Y-%m-%d', timestamp, 'unixepoch')` format the daemon's
    /// roll-up uses, so day strings sort + compare as text.
    private static func isoDay(daysAgo: Int) -> String {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd"
        formatter.timeZone = TimeZone(identifier: "UTC")
        formatter.locale = Locale(identifier: "en_US_POSIX")
        return formatter.string(from: Date().addingTimeInterval(-Double(daysAgo) * 86400))
    }

    /// Identifiable wrapper so SwiftUI's Table can key rows by composite
    /// (day, category, signer, path) without requiring AggregateRow itself
    /// to gain an id property in the Core target.
    fileprivate struct IdentifiedAggregate: Identifiable {
        let id: String
        let row: EventStore.AggregateRow
    }

    private var identifiedAggregates: [IdentifiedAggregate] {
        aggregateRows.map {
            IdentifiedAggregate(
                id: "\($0.day)|\($0.category.rawValue)|\($0.processSigner)|\($0.processPath)",
                row: $0
            )
        }
    }

    @ViewBuilder
    private var aggregateTable: some View {
        if aggregateRows.isEmpty {
            VStack(spacing: 12) {
                Spacer()
                Image(systemName: "tray")
                    .font(.system(size: 48))
                    .foregroundColor(.secondary.opacity(0.5))
                    .accessibilityHidden(true)
                Text(String(
                    localized: "events.noAggregates",
                    defaultValue: "No aggregated events for this range — the daemon's daily roll-up runs every 6 hours"
                ))
                .font(.headline)
                .foregroundColor(.secondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal)
                Spacer()
            }
            .frame(maxWidth: .infinity)
        } else {
            Table(identifiedAggregates) {
                TableColumn(String(localized: "events.day", defaultValue: "Day")) { agg in
                    Text(agg.row.day)
                        .font(.system(.caption, design: .monospaced))
                }
                .width(min: 90, ideal: 100, max: 120)

                TableColumn(String(localized: "events.category", defaultValue: "Category")) { agg in
                    // Cross-module rawValue bridge: aggregate rows carry
                    // MacCrabCore.EventCategory; CategoryBadge takes the
                    // MacCrabApp local mirror. Same raw values by design.
                    if let appCat = EventCategory(rawValue: agg.row.category.rawValue) {
                        CategoryBadge(category: appCat)
                    } else {
                        Text(agg.row.category.rawValue.capitalized).font(.caption2)
                    }
                }
                .width(min: 70, ideal: 90, max: 110)

                TableColumn(String(localized: "events.signer", defaultValue: "Signer")) { agg in
                    Text(agg.row.processSigner.isEmpty ? "—" : agg.row.processSigner)
                        .font(.system(.caption, design: .monospaced))
                        .foregroundColor(agg.row.processSigner.isEmpty ? .secondary : .primary)
                }
                .width(min: 70, ideal: 90, max: 120)

                TableColumn(String(localized: "events.path", defaultValue: "Process Path")) { agg in
                    Text(agg.row.processPath.isEmpty ? "—" : agg.row.processPath)
                        .font(.system(.caption, design: .monospaced))
                        .lineLimit(1)
                        .truncationMode(.middle)
                }

                TableColumn(String(localized: "events.count", defaultValue: "Count")) { agg in
                    Text("\(agg.row.count)")
                        .font(.system(.caption, design: .monospaced))
                        .foregroundColor(agg.row.count > 1000 ? .orange : .primary)
                }
                .width(min: 60, ideal: 70, max: 90)
            }
        }
    }

    /// Recompute the filtered+sorted cache. Called from .onAppear,
    /// .onReceive(appState.$events), and .onChange of any filter input.
    /// Pure function over current state — no @Published mutations.
    ///
    /// v1.8.0: free-text search no longer filters in-memory. The 500-row
    /// in-memory window meant `bash` matched ~5/100K events; the user thought
    /// the search was broken. Search now goes through `appState.loadEvents
    /// (filter:)`, which hits the FTS5 index, and the in-memory pass below
    /// only handles category + time-range — the two filters that don't have
    /// a database-side equivalent and cheap to evaluate locally.
    private func recomputeFilter() {
        var results = appState.events

        if let category = filterCategory {
            results = results.filter { $0.category == category }
        }

        if let seconds = timeRange.seconds {
            let cutoff = Date().addingTimeInterval(-seconds)
            results = results.filter { $0.timestamp >= cutoff }
        }

        filteredCache = results.sorted(using: sortOrder)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            // Toolbar
            HStack(spacing: 12) {
                Text(String(localized: "events.title", defaultValue: "Events"))
                    .font(.title2)
                    .fontWeight(.bold)

                Text("\(filteredCache.count)")
                    .font(.caption)
                    .padding(.horizontal, 8)
                    .padding(.vertical, 2)
                    .background(Color.secondary.opacity(0.2))
                    .clipShape(Capsule())

                Picker("Time", selection: $timeRange) {
                    ForEach(TimeRange.allCases, id: \.self) { range in
                        Text(range.rawValue).tag(range)
                    }
                }
                .pickerStyle(.segmented)
                .frame(width: 350)

                Spacer()

                // Category filter
                Picker("Category", selection: $filterCategory) {
                    Text("All Categories").tag(EventCategory?.none)
                    Divider()
                    ForEach(EventCategory.allCases, id: \.self) { cat in
                        Text(cat.rawValue.capitalized).tag(EventCategory?.some(cat))
                    }
                }
                .frame(width: 160)
                .accessibilityLabel("Filter by event category")

                TextField("Filter...", text: $filterText)
                    .textFieldStyle(.roundedBorder)
                    .frame(width: 200)

                Button {
                    Task { await appState.loadEvents() }
                } label: {
                    Image(systemName: "arrow.clockwise")
                }
                .controlSize(.small)
                .help("Reload events")
                .accessibilityLabel("Reload events")
                .keyboardShortcut("r", modifiers: .command)

                Divider()
                    .frame(height: 16)

                Toggle(String(localized: "events.autoScroll", defaultValue: "Auto-scroll"), isOn: $autoScroll)
                    .toggleStyle(.checkbox)
                    .font(.caption)
                    .accessibilityLabel("Auto-scroll to newest events")

                Button {
                    isPaused.toggle()
                } label: {
                    Image(systemName: isPaused ? "play.fill" : "pause.fill")
                    Text(isPaused
                        ? String(localized: "events.resume", defaultValue: "Resume")
                        : String(localized: "events.pause", defaultValue: "Pause"))
                }
                .buttonStyle(.bordered)
                .controlSize(.small)
                .accessibilityLabel(isPaused ? "Resume event stream" : "Pause event stream")
                .keyboardShortcut(" ", modifiers: [])
            }
            .padding()

            Divider()

            // v1.8.0: aggregate-mode banner. Shown whenever the user picks a
            // time range past the 24h hot tier — explains why detail rows
            // are sparse / aggregate columns are different.
            if isAggregateMode {
                HStack(spacing: 8) {
                    Image(systemName: "chart.bar.fill")
                        .foregroundColor(.accentColor)
                        .font(.caption)
                        .accessibilityHidden(true)
                    Text(String(
                        localized: "events.aggregateModeBanner",
                        defaultValue: "Showing daily summaries — narrow the time range to last 24h or shorter for per-event detail"
                    ))
                    .font(.caption)
                    .foregroundColor(.accentColor)
                    Spacer()
                }
                .padding(.horizontal)
                .padding(.vertical, 6)
                .background(Color.accentColor.opacity(0.08))
            }

            // Event table
            if isAggregateMode {
                aggregateTable
            } else if filteredCache.isEmpty {
                VStack(spacing: 12) {
                    Spacer()
                    Image(systemName: "list.bullet.rectangle")
                        .font(.system(size: 48))
                        .foregroundColor(.secondary.opacity(0.5))
                        .accessibilityHidden(true)
                    Text(String(localized: "events.noMatch", defaultValue: "No events matching current filters"))
                        .font(.headline)
                        .foregroundColor(.secondary)
                    if filterCategory != nil || !filterText.isEmpty {
                        Button(String(localized: "events.clearFilters", defaultValue: "Clear Filters")) {
                            filterCategory = nil
                            filterText = ""
                        }
                    }
                    Spacer()
                }
                .frame(maxWidth: .infinity)
            } else {
                HStack(spacing: 0) {
                    Table(filteredCache, selection: $selectedEventID, sortOrder: $sortOrder) {
                        TableColumn("Time", value: \.timestamp) { event in
                            Text(event.dateTimeString)
                                .font(.system(.caption, design: .monospaced))
                        }
                        .width(min: 120, ideal: 150, max: 180)

                        TableColumn("Action", value: \.action) { event in
                            Text(RuleTranslations.translateAction(event.action))
                                .fontWeight(.medium)
                                .foregroundColor(event.actionColor)
                        }
                        .width(min: 60, ideal: 80, max: 100)

                        TableColumn("Category", value: \.category.rawValue) { event in
                            CategoryBadge(category: event.category)
                        }
                        .width(min: 70, ideal: 90, max: 110)

                        TableColumn("Process", value: \.processName) { event in
                            Text("\(event.processName) (\(event.pid))")
                        }
                        .width(min: 120, ideal: 160, max: 220)

                        TableColumn("Detail", value: \.detail) { event in
                            Text(event.detail)
                                .lineLimit(1)
                                .help(event.detail)
                        }

                        TableColumn("Signer", value: \.signerType) { event in
                            SignerBadge(signerType: event.signerType)
                        }
                        .width(min: 60, ideal: 80, max: 100)
                    }

                    // Event detail panel — only when selected
                    if let selectedID = selectedEventID,
                       let event = filteredCache.first(where: { $0.id == selectedID }) {
                        Divider()
                        EventDetailPanel(event: event)
                            .frame(minWidth: 280, idealWidth: 350, maxWidth: 450)
                            .transition(reduceMotion ? .opacity : .move(edge: .trailing))
                    }
                }
                .animation(reduceMotion ? nil : .easeInOut(duration: 0.2), value: selectedEventID)
            }

            // v1.8.0: keyset-paginated "Load older" footer. Sits between the
            // table and the live-status bar so the live indicator stays
            // anchored at the bottom. Hidden once we hit the end-of-table.
            if appState.hasMoreEvents {
                HStack {
                    Spacer()
                    Button {
                        Task { await appState.loadOlderEvents() }
                    } label: {
                        Label(
                            String(localized: "events.loadOlder", defaultValue: "Load older"),
                            systemImage: "arrow.down.circle"
                        )
                    }
                    .buttonStyle(.bordered)
                    .controlSize(.small)
                    Spacer()
                }
                .padding(.vertical, 6)
                .background(.bar)
            }

            // Status bar
            HStack {
                if appState.eventSearchActive {
                    // v1.8.0: search results are FTS-ranked, not time-ordered.
                    // Make it explicit so the user doesn't expect newest-first
                    // and isn't surprised when the live counter still ticks.
                    Image(systemName: "magnifyingglass")
                        .foregroundColor(.accentColor)
                        .accessibilityHidden(true)
                    Text(String(localized: "events.searchMode", defaultValue: "Search results — clear to resume live"))
                        .foregroundColor(.accentColor)
                } else if isPaused {
                    Image(systemName: "pause.circle.fill")
                        .foregroundColor(.orange)
                        .accessibilityHidden(true)
                    Text(String(localized: "events.paused", defaultValue: "Paused"))
                        .foregroundColor(.orange)
                } else {
                    Image(systemName: "circle.fill")
                        .foregroundColor(.green)
                        .font(.system(size: 6))
                        .accessibilityHidden(true)
                    Text(String(localized: "events.live", defaultValue: "Live"))
                        .foregroundColor(.green)
                }
                Spacer()
                Text("\(appState.eventsPerSecond) events/sec")
                    .foregroundColor(.secondary)
            }
            .font(.caption)
            .padding(.horizontal)
            .padding(.vertical, 6)
            .background(.bar)
        }
        .onAppear {
            recomputeFilter()
        }
        // v1.8.0: filterText drives a debounced FTS5 fetch. SwiftUI cancels
        // the previous task on every keystroke, so the only one that fires
        // store.search() is the one whose 300ms quiet window elapses. Empty
        // string returns to live mode (regular events query + poll prepend).
        .task(id: filterText) {
            do { try await Task.sleep(nanoseconds: 300_000_000) } catch { return }
            if filterText.isEmpty {
                await appState.loadEvents()
            } else {
                await appState.loadEvents(filter: filterText)
            }
        }
        // v1.8.0: refresh aggregate rows whenever the time range crosses the
        // 24h boundary or the category filter changes. Runs only in aggregate
        // mode — inside 24h the filteredCache + live polling is canonical.
        .task(id: aggregateInputsKey) {
            if isAggregateMode {
                let sinceDay = Self.isoDay(daysAgo: rangeDays)
                aggregateRows = await appState.fetchAggregates(
                    sinceDay: sinceDay,
                    category: filterCategory.map { MacCrabCore.EventCategory(rawValue: $0.rawValue) } ?? nil
                )
            } else {
                aggregateRows = []
            }
        }
        // v1.7.11: recompute the cached filtered+sorted list only when an
        // input actually changes. Without these, the body's previous use
        // of `timeFilteredEvents` (computed property) re-filtered and
        // re-sorted on every body re-evaluation — and SwiftUI re-evaluates
        // body on every @Published mutation in AppState (heartbeat,
        // agentLineage, etc.), driving 333 Auto Layout constraint
        // allocations/sec via NSTableView rebinds.
        .onReceive(appState.$events) { _ in recomputeFilter() }
        .onChange(of: filterCategory) { _ in recomputeFilter() }
        .onChange(of: timeRange) { _ in recomputeFilter() }
        .onChange(of: sortOrder) { _ in recomputeFilter() }
    }
}

// MARK: - CategoryBadge

/// Small badge showing the event category with an appropriate color.
private struct CategoryBadge: View {
    let category: EventCategory

    private var color: Color {
        switch category {
        case .process:        return .green
        case .file:           return .blue
        case .network:        return .purple
        case .authentication: return .orange
        case .tcc:            return .red
        case .registry:       return .secondary
        }
    }

    var body: some View {
        Text(category.rawValue.capitalized)
            .font(.caption2)
            .fontWeight(.medium)
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .background(color.opacity(0.15))
            .foregroundColor(color)
            .clipShape(Capsule())
    }
}

// MARK: - Event Detail Panel

private struct EventDetailPanel: View {
    let event: EventViewModel

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                HStack {
                    Text(RuleTranslations.translateAction(event.action))
                        .font(.headline)
                        .foregroundColor(event.actionColor)
                    CategoryBadge(category: event.category)
                    Spacer()
                }

                Text(event.dateTimeString)
                    .font(.caption)
                    .foregroundColor(.secondary)

                GroupBox(String(localized: "eventDetail.process", defaultValue: "Process")) {
                    VStack(alignment: .leading, spacing: 6) {
                        EventDetailRow(label: "Name", value: event.processName)
                        EventDetailRow(label: "PID", value: String(event.pid))
                        if !event.signerType.isEmpty {
                            EventDetailRow(label: "Signer", value: event.signerType)
                        }
                    }.padding(4)
                }

                GroupBox(String(localized: "eventDetail.detail", defaultValue: "Detail")) {
                    Text(event.detail)
                        .font(.system(.body, design: .monospaced))
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(4)
                }

                GroupBox(String(localized: "eventDetail.metadata", defaultValue: "Event Metadata")) {
                    VStack(alignment: .leading, spacing: 6) {
                        EventDetailRow(label: "ID", value: event.id.uuidString)
                        EventDetailRow(label: "Category", value: event.category.rawValue)
                        EventDetailRow(label: "Action", value: RuleTranslations.translateAction(event.action))
                    }.padding(4)
                }

                // Copy button
                Button {
                    NSPasteboard.general.clearContents()
                    let text = """
                    Event: \(event.action) (\(event.category.rawValue))
                    Time: \(event.dateTimeString)
                    Process: \(event.processName) (PID \(event.pid))
                    Signer: \(event.signerType)
                    Detail: \(event.detail)
                    ID: \(event.id.uuidString)
                    """
                    NSPasteboard.general.setString(text, forType: .string)
                } label: {
                    Label(String(localized: "events.copyDetails", defaultValue: "Copy Event Details"), systemImage: "doc.on.doc")
                }
                .controlSize(.large)

                Spacer()
            }.padding()
        }.background(Color(nsColor: .controlBackgroundColor))
    }
}

private struct EventDetailRow: View {
    let label: String
    let value: String
    var body: some View {
        HStack(alignment: .top) {
            Text(label).font(.caption).foregroundColor(.secondary).frame(width: 60, alignment: .trailing)
            Text(value).font(.system(.subheadline, design: .monospaced)).textSelection(.enabled)
        }
    }
}

