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
    @State private var filterText: String
    @State private var filterCategory: EventCategory? = nil

    /// `initialFilterText` lets a caller pre-populate the FTS filter
    /// when navigating in via "Investigate in Events" from an alert.
    /// Without this, the alert→events transition lost the alert's
    /// process / event-id context entirely; the user had to re-type
    /// the search term that V2 already had in hand. Default is empty
    /// so existing direct-mount call sites stay unchanged.
    /// `firstFilterRun` is true on the very first body→.task(id: filterText)
    /// fire when initialFilterText is non-empty. Used to skip the
    /// 300 ms debounce on that first run so the prefilled filter
    /// lands instantly. After the first run it's set to false and
    /// subsequent keystroke-driven debounce semantics apply.
    @State private var firstFilterRun: Bool

    /// Optional centring timestamp set by an "Investigate in Events"
    /// click on an alert / trace. When non-nil, the EventStream
    /// query is bounded to `[centerTime ± centerHalfWindowSeconds]`
    /// so the user lands on events that fired AROUND the alert,
    /// not just anything matching the filter in the last 24 h. Nil
    /// for ordinary direct mounts.
    let initialCenterTime: Date?
    let centerHalfWindowSeconds: TimeInterval

    init(
        appState: AppState,
        initialFilterText: String = "",
        initialCenterTime: Date? = nil,
        centerHalfWindowSeconds: TimeInterval = 30 * 60
    ) {
        self.appState = appState
        self._filterText = State(initialValue: initialFilterText)
        self._firstFilterRun = State(initialValue: !initialFilterText.isEmpty)
        self.initialCenterTime = initialCenterTime
        self.centerHalfWindowSeconds = centerHalfWindowSeconds
    }

    /// v1.18: alerts whose triggering event is this event (alert.eventId ==
    /// the event UUID). Combines the in-memory recent + dashboard alert pools
    /// (deduped) so the event detail panel can show "this event triggered N
    /// alerts" — the fuller alert view from the events side.
    private func triggeredAlerts(for event: EventViewModel) -> [AlertViewModel] {
        let key = event.id.uuidString
        var seen = Set<String>()
        return (appState.recentAlerts + appState.dashboardAlerts)
            .filter { $0.eventId == key }
            .filter { seen.insert($0.id).inserted }
    }

    @State private var isPaused: Bool = false
    @State private var selectedEventID: EventViewModel.ID? = nil
    /// Aggregate-table selection so warm-tier summary rows get a right-click
    /// drill-in (they were previously inert despite the banner telling the
    /// user to "narrow the range for per-event detail"). (#5)
    @State private var selectedAggregateID: EventStream.IdentifiedAggregate.ID? = nil
    // v1.8.0: default to Last 24h so the user lands in the hot tier on
    // open — `.all` immediately put them in aggregate mode against an
    // empty rollup table on a fresh DB, which read as broken.
    @State private var timeRange: TimeRange = .last24h
    @State private var sortOrder = [KeyPathComparator(\EventViewModel.timestamp, order: .reverse)]
    @Environment(\.accessibilityReduceMotion) var reduceMotion
    /// v1.8.0: Discover-style time histogram toggle. Off by default —
    /// existing users open the Events tab to today's flat table; SIEM
    /// chrome is opt-in. AppStorage persists the choice across launches.
    @AppStorage("events.showHistogram") private var showHistogram: Bool = false

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
    /// v1.8.0 polish: SQL-side histogram bin counts. Re-queried whenever
    /// the time range, category filter, or refresh tick changes — the
    /// previous filteredCache-derived path was broken on high-volume
    /// hosts because the 500-row in-memory window covered ~2 seconds.
    @State private var histogramRows: [(Date, Int)] = []
    /// #16: bumped on every live prepend so the histogram task re-queries in
    /// step with the table. The chart previously refreshed only on time-range
    /// / category changes, so it drifted stale relative to the live stream —
    /// the "refresh tick" the histogramRows doc-comment named was never wired.
    @State private var histogramRefreshTick: Int = 0
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

    /// `filterCategory` bridged to the Core enum so `loadEvents` can push
    /// the category predicate DB-side. nil ("All Categories") = no
    /// predicate. Raw values are 1:1 with the app mirror, so the failable
    /// init never returns nil for a real case (same pattern the aggregate /
    /// histogram tasks already use).
    private var coreCategory: MacCrabCore.EventCategory? {
        filterCategory.map { MacCrabCore.EventCategory(rawValue: $0.rawValue) } ?? nil
    }

    /// Reload key for the hot-tier (non-search) event query. Range OR
    /// category changing must re-hit the DB: category is now a DB-side
    /// predicate (loadEvents forwards it), so a category change has to
    /// re-query rather than only paring down the loaded ~500-row window
    /// in memory (which undercounts on busy hosts). Same value shape as
    /// aggregateInputsKey but drives the per-event table task.
    private var eventQueryKey: String {
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

    /// v1.18.1: stored, not computed. The computed form re-mapped a fresh
    /// array on every body re-evaluation and rebound the NSTableView-backed
    /// Table to it — the same constraint-churn class the filteredCache
    /// comment above documents (v1.7.11), reachable whenever the user parks
    /// on a >24h range. Assigned alongside aggregateRows in the .task below.
    @State private var identifiedAggregates: [IdentifiedAggregate] = []

    private static func identify(_ rows: [EventStore.AggregateRow]) -> [IdentifiedAggregate] {
        rows.map {
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
                    .scaledSystem(48)
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
            Table(identifiedAggregates, selection: $selectedAggregateID) {
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
            // #5: warm-tier summary rows can now drill into the hot-tier
            // per-event table (banner previously told users to "narrow the
            // range for per-event detail" but rows were inert).
            .contextMenu(forSelectionType: IdentifiedAggregate.ID.self) { ids in
                if let id = ids.first,
                   let agg = identifiedAggregates.first(where: { $0.id == id }) {
                    Button {
                        drillIntoAggregate(agg.row)
                    } label: {
                        Label(String(localized: "events.aggregate.drillIn",
                                     defaultValue: "Show Events for This Process"),
                              systemImage: "list.bullet.rectangle")
                    }
                    Button {
                        copyAggregate(agg.row)
                    } label: {
                        Label(String(localized: "events.copyRow", defaultValue: "Copy Row"),
                              systemImage: "doc.on.doc")
                    }
                }
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
    /// Compute the [since, until] bounds for `appState.loadEvents`.
    /// Pre-fix `loadEvents` was called with no time bound; the FTS5
    /// query happily returned 30-day-old matches when the user
    /// expected "events around the time the alert fired". Now:
    /// - If `initialCenterTime` is set (set by Investigate-in-Events
    ///   from an alert/trace), narrow to centre ± half-window.
    /// - Otherwise the user's `timeRange` chip drives a [now-window,
    ///   now] bound; .all returns [.distantPast, .distantFuture].
    private func computeEventsTimeBounds() -> (since: Date, until: Date) {
        if let centre = initialCenterTime {
            let half = centerHalfWindowSeconds
            return (centre.addingTimeInterval(-half),
                    centre.addingTimeInterval(half))
        }
        let since = timeRange.seconds.map { Date().addingTimeInterval(-$0) } ?? .distantPast
        return (since, .distantFuture)
    }

    /// Effective [endingAt, span] for the hot-tier histogram. During an
    /// "Investigate in Events" navigation (`initialCenterTime` set) the
    /// histogram must describe the SAME window the table query uses
    /// (centre ± half-window) instead of one ending "now" — otherwise the
    /// bars and the rows below them cover different time ranges. (#2)
    private var histogramWindow: (endingAt: Date, span: TimeInterval) {
        if let centre = initialCenterTime {
            return (centre.addingTimeInterval(centerHalfWindowSeconds),
                    centerHalfWindowSeconds * 2)
        }
        return (Date(), timeRange.seconds ?? 86400)
    }

    /// Bin granularity for the hot-tier histogram. `.last7d` / `.all` always
    /// render in daily aggregate mode (see `isAggregateMode`), so no hot-tier
    /// granularity is defined for them — the old `.last7d → .sixHour` mapping
    /// was unreachable dead code. (#8)
    private var hotHistogramGranularity: HistogramGranularity {
        if initialCenterTime != nil {
            // Centred window is typically an hour wide; pick bins that give a
            // readable ~30-60 bars regardless of which chip is selected.
            let span = centerHalfWindowSeconds * 2
            if span < 7_200 { return .minute }      // ≤2h
            if span < 86_400 { return .thirtyMin }  // ≤24h
            return .sixHour
        }
        switch timeRange {
        case .lastHour: return .minute
        case .last24h:  return .thirtyMin
        default:        return .hour            // .last7d / .all never reach here
        }
    }

    /// Histogram task id: the range/category composite plus the live refresh
    /// tick, so a live prepend re-runs the SQL bin query. (#16)
    private var histogramInputsKey: String {
        "\(aggregateInputsKey)|\(histogramRefreshTick)"
    }

    /// True once the oldest already-loaded event predates the active window's
    /// floor — further "Load older" pages fall entirely outside the window and
    /// would be filtered straight back out, so the button looks dead. Hide it
    /// instead. Not applied when centred or for `.all` (no lower bound). (#11)
    private var loadOlderCrossedWindow: Bool {
        guard initialCenterTime == nil, let seconds = timeRange.seconds else { return false }
        let cutoff = Date().addingTimeInterval(-seconds)
        guard let oldest = appState.events.map(\.timestamp).min() else { return false }
        return oldest < cutoff
    }

    // MARK: - Row actions (context menus, drill-in, export)

    /// Copy one or more events as a plain-text block (mirrors the detail
    /// panel's single-event copy). Used by the table row context menu. (#6)
    private func copyEventDetails(_ events: [EventViewModel]) {
        let blocks = events.map { e in
            """
            Event: \(e.action) (\(e.category.rawValue))
            Time: \(e.dateTimeString)
            Process: \(e.processName) (PID \(e.pid))
            Signer: \(e.signerType)
            Detail: \(e.detail)
            ID: \(e.id.uuidString)
            """
        }
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(blocks.joined(separator: "\n\n"), forType: .string)
    }

    /// Pivot from a warm-tier aggregate summary into the hot-tier per-event
    /// table filtered by the same category + process. The hot tier only
    /// retains recent per-event detail, so this narrows the range to Last 24h
    /// and prefills the process filter; older days may have no per-event rows
    /// left (retention), which is expected. (#5)
    private func drillIntoAggregate(_ row: EventStore.AggregateRow) {
        if let appCat = EventCategory(rawValue: row.category.rawValue) {
            filterCategory = appCat
        }
        filterText = row.processPath.isEmpty ? row.processSigner : row.processPath
        timeRange = .last24h
    }

    private func copyAggregate(_ row: EventStore.AggregateRow) {
        let text = "\(row.day)\t\(row.category.rawValue)\t\(row.processSigner)\t\(row.processPath)\t\(row.count)"
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
    }

    /// RFC-4180 CSV field escaping: quote when the value contains a comma,
    /// quote, or newline; double any embedded quotes.
    private func csvField(_ s: String) -> String {
        if s.contains(",") || s.contains("\"") || s.contains("\n") {
            return "\"" + s.replacingOccurrences(of: "\"", with: "\"\"") + "\""
        }
        return s
    }

    /// Prompt for a destination and write `contents`. (#15)
    private func saveExport(_ contents: String, suggestedName: String) {
        let panel = NSSavePanel()
        panel.nameFieldStringValue = suggestedName
        panel.canCreateDirectories = true
        panel.title = String(localized: "events.export.title", defaultValue: "Export Events")
        if panel.runModal() == .OK, let url = panel.url {
            try? contents.write(to: url, atomically: true, encoding: .utf8)
        }
    }

    private func exportEventsCSV() {
        let header = "Time,Action,Category,Process,PID,Signer,Detail"
        let rows = filteredCache.map { e in
            [e.dateTimeString,
             RuleTranslations.translateAction(e.action),
             e.category.rawValue,
             e.processName,
             String(e.pid),
             e.signerType,
             e.detail].map(csvField).joined(separator: ",")
        }
        saveExport(([header] + rows).joined(separator: "\n"), suggestedName: "maccrab-events.csv")
    }

    private func exportEventsJSON() {
        let iso = ISO8601DateFormatter()
        let objects: [[String: Any]] = filteredCache.map { e in
            ["id": e.id.uuidString,
             "timestamp": iso.string(from: e.timestamp),
             "action": e.action,
             "category": e.category.rawValue,
             "process": e.processName,
             "pid": Int(e.pid),
             "signer": e.signerType,
             "detail": e.detail]
        }
        guard let data = try? JSONSerialization.data(withJSONObject: objects, options: [.prettyPrinted, .sortedKeys]),
              let str = String(data: data, encoding: .utf8) else { return }
        saveExport(str, suggestedName: "maccrab-events.json")
    }

    private func exportAggregatesCSV() {
        let header = "Day,Category,Signer,Process Path,Count"
        let rows = identifiedAggregates.map { a in
            [a.row.day,
             a.row.category.rawValue,
             a.row.processSigner,
             a.row.processPath,
             String(a.row.count)].map(csvField).joined(separator: ",")
        }
        saveExport(([header] + rows).joined(separator: "\n"), suggestedName: "maccrab-event-aggregates.csv")
    }

    private func recomputeFilter() {
        var results = appState.events

        if let category = filterCategory {
            results = results.filter { $0.category == category }
        }

        // C2: when centred (an "Investigate in Events" click from an
        // alert/trace set `initialCenterTime`), the DB query is already
        // bounded to centre ± half-window by computeEventsTimeBounds().
        // Re-applying the live `timeRange` cutoff here would drop every
        // event older than the chip — producing an EMPTY table for any
        // alert past the range (default 24h). Filter to the same centred
        // window the query used instead. In the normal (non-centred) case
        // the user's timeRange chip still drives the cutoff, unchanged.
        if initialCenterTime != nil {
            let bounds = computeEventsTimeBounds()
            results = results.filter { $0.timestamp >= bounds.since && $0.timestamp <= bounds.until }
        } else if let seconds = timeRange.seconds {
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
                    // #9: `.registry` has no macOS collector — every event that
                    // reaches this view is process/file/network/auth/tcc. Drop
                    // it so the picker doesn't offer a permanently-empty option.
                    ForEach(EventCategory.allCases.filter { $0 != .registry }, id: \.self) { cat in
                        Text(cat.rawValue.capitalized).tag(EventCategory?.some(cat))
                    }
                }
                .frame(width: 160)
                .accessibilityLabel("Filter by event category")

                TextField("Filter...", text: $filterText)
                    .textFieldStyle(.roundedBorder)
                    .frame(width: 200)

                Button {
                    Task {
                        let bounds = computeEventsTimeBounds()
                        if filterText.isEmpty {
                            await appState.loadEvents(since: bounds.since, until: bounds.until, category: coreCategory)
                        } else {
                            await appState.loadEvents(
                                filter: filterText,
                                since: bounds.since,
                                until: bounds.until,
                                category: coreCategory
                            )
                        }
                    }
                } label: {
                    Image(systemName: "arrow.clockwise")
                }
                .controlSize(.small)
                .help("Reload events")
                .accessibilityLabel("Reload events")
                .keyboardShortcut("r", modifiers: .command)

                Divider()
                    .frame(height: 16)

                // v1.8.0: SIEM-style histogram toggle. Hidden behind a
                // small icon button so the simple-mode UX stays clean
                // for users who want flat-table-only.
                Button {
                    showHistogram.toggle()
                } label: {
                    Image(systemName: showHistogram ? "chart.bar.fill" : "chart.bar")
                }
                .controlSize(.small)
                .help(showHistogram
                    ? String(localized: "events.histogramHide", defaultValue: "Hide time histogram")
                    : String(localized: "events.histogramShow", defaultValue: "Show time histogram"))
                .accessibilityLabel("Toggle time histogram")

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
                // #17: was a bare spacebar shortcut that fired while the user
                // typed a space into the Filter field (and vice-versa). Move it
                // to ⌘P so it no longer competes with text entry.
                .keyboardShortcut("p", modifiers: .command)
                .help(isPaused
                    ? String(localized: "events.resume.help", defaultValue: "Resume the live event stream (⌘P)")
                    : String(localized: "events.pause.help", defaultValue: "Pause the live event stream (⌘P)"))

                // #15: export the currently-shown rows (per-event in hot mode,
                // aggregate summaries past 24h) to CSV/JSON.
                Menu {
                    Button {
                        if isAggregateMode { exportAggregatesCSV() } else { exportEventsCSV() }
                    } label: {
                        Label(String(localized: "events.export.csv", defaultValue: "Export as CSV"), systemImage: "tablecells")
                    }
                    if !isAggregateMode {
                        Button {
                            exportEventsJSON()
                        } label: {
                            Label(String(localized: "events.export.json", defaultValue: "Export as JSON"), systemImage: "curlybraces")
                        }
                    }
                } label: {
                    Image(systemName: "square.and.arrow.up")
                }
                .menuIndicator(.hidden)
                .controlSize(.small)
                .fixedSize()
                .disabled(isAggregateMode ? identifiedAggregates.isEmpty : filteredCache.isEmpty)
                .help(String(localized: "events.export.help", defaultValue: "Export the current events to CSV or JSON"))
                .accessibilityLabel("Export events")
            }
            .padding()

            Divider()

            // v1.8.0: time histogram (Discover-style). Bars are the hourly
            // count in hot-tier mode and the daily count in aggregate mode.
            // Toggled by the toolbar chart icon; off by default so existing
            // users see today's familiar layout until they opt in.
            if showHistogram {
                // Granularity + window come from hotHistogramGranularity /
                // histogramWindow so the bars honour an "Investigate in Events"
                // centre time (#2) rather than always ending "now". The daily
                // (aggregate) branch stays now-anchored to match its now-based
                // aggregate fetch.
                let hotGranularity = hotHistogramGranularity
                let dailySpanDays = max(1, Int((timeRange.seconds ?? (7 * 86400)) / 86400))
                EventTimeHistogram(
                    bins: isAggregateMode
                        ? EventTimeHistogram.dailyBins(from: aggregateRows, endingAt: Date(), spanDays: dailySpanDays)
                        : EventTimeHistogram.bins(fromSQL: histogramRows, granularity: hotGranularity, endingAt: histogramWindow.endingAt, spanSeconds: histogramWindow.span),
                    unitLabel: isAggregateMode ? "Day" : "Time",
                    granularity: isAggregateMode ? .day : hotGranularity
                )
                // #14: the SQL histogram counts ALL events in the window, not
                // just the current FTS matches (fetchHistogramBins takes no text
                // filter). Say so, so the bars aren't read as the filtered table.
                if appState.eventSearchActive {
                    Text(String(localized: "events.histogramAllEvents",
                                defaultValue: "Histogram shows all events in range — not filtered by the search text"))
                        .font(.caption2)
                        .foregroundColor(.secondary)
                        .padding(.horizontal)
                        .padding(.bottom, 2)
                }
                Divider()
            }

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
                        .scaledSystem(48)
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
                    // #6: per-row actions — copy the selected event(s), or
                    // pivot the filter to the row's process.
                    .contextMenu(forSelectionType: EventViewModel.ID.self) { ids in
                        let selected = filteredCache.filter { ids.contains($0.id) }
                        if !selected.isEmpty {
                            Button {
                                copyEventDetails(selected)
                            } label: {
                                Label(String(localized: "events.copyDetails", defaultValue: "Copy Event Details"),
                                      systemImage: "doc.on.doc")
                            }
                            if let first = selected.first {
                                Button {
                                    filterText = first.processName
                                } label: {
                                    Label(String(localized: "events.filterByProcess",
                                                 defaultValue: "Filter by \"\(first.processName)\""),
                                          systemImage: "line.3.horizontal.decrease.circle")
                                }
                            }
                        }
                    }

                    // Event detail panel — only when selected
                    if let selectedID = selectedEventID,
                       let event = filteredCache.first(where: { $0.id == selectedID }) {
                        Divider()
                        EventDetailPanel(event: event, triggeredAlerts: triggeredAlerts(for: event))
                            .frame(minWidth: 280, idealWidth: 350, maxWidth: 450)
                            .transition(reduceMotion ? .opacity : .move(edge: .trailing))
                    }
                }
                .animation(reduceMotion ? nil : .easeInOut(duration: 0.2), value: selectedEventID)
            }

            // v1.8.0: keyset-paginated "Load older" footer. Sits between the
            // table and the live-status bar so the live indicator stays
            // anchored at the bottom. Hidden once we hit the end-of-table OR
            // when the user is in aggregate mode (the cursor only makes
            // sense over the hot-tier events table, not over rollup rows).
            if appState.hasMoreEvents && !isAggregateMode && !loadOlderCrossedWindow {
                HStack {
                    Spacer()
                    Button {
                        Task {
                            await appState.loadOlderEvents(category: coreCategory)
                            // #13: an explicit user fetch — reflect it even
                            // while Paused (Pause freezes the live firehose,
                            // not on-demand paging, so the onReceive recompute
                            // that's gated on !isPaused would otherwise swallow
                            // the appended rows).
                            recomputeFilter()
                        }
                    } label: {
                        Label(
                            appState.isLoadingOlderEvents
                                ? String(localized: "events.loadOlder.loading", defaultValue: "Loading…")
                                : String(localized: "events.loadOlder", defaultValue: "Load older"),
                            systemImage: appState.isLoadingOlderEvents ? "hourglass" : "arrow.down.circle"
                        )
                    }
                    .buttonStyle(.bordered)
                    .controlSize(.small)
                    .disabled(appState.isLoadingOlderEvents)
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
                } else if appState.heartbeat?.isStale ?? true {
                    // B5: don't reassure with green "Live" when the engine
                    // isn't reporting. A stale (>120s) or missing heartbeat
                    // means the daemon is hung, crashed, or replaced by a
                    // no-op — the stream can read "Live" while nothing is
                    // actually being collected. Show a muted stale state.
                    Image(systemName: "moon.zzz.fill")
                        .foregroundColor(.secondary)
                        .accessibilityHidden(true)
                    Text(String(localized: "events.stale", defaultValue: "Daemon not reporting"))
                        .foregroundColor(.secondary)
                } else {
                    Image(systemName: "circle.fill")
                        .foregroundColor(.green)
                        .scaledSystem(6)
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
            // v1.10 fix: when this view mounts with a non-empty
            // initialFilterText (the "Investigate in Events" path),
            // immediately mark eventSearchActive so the 10s
            // incremental poll's prepend can't corrupt the filtered
            // result, and run a synchronous loadEvents(filter:) so
            // the user sees filtered rows on FIRST paint instead of
            // unfiltered rows for ~300 ms then filtered.
            if !filterText.isEmpty {
                appState.eventSearchActive = true
                let bounds = computeEventsTimeBounds()
                Task {
                    await appState.loadEvents(
                        filter: filterText,
                        since: bounds.since,
                        until: bounds.until,
                        category: coreCategory
                    )
                }
            }
            recomputeFilter()
        }
        // v1.8.0: filterText drives a debounced FTS5 fetch. SwiftUI cancels
        // the previous task on every keystroke, so the only one that fires
        // store.search() is the one whose 300ms quiet window elapses. Empty
        // string returns to live mode (regular events query + poll prepend).
        // First-render bypass: if `firstFilterRun` is true (set by init when
        // initialFilterText was non-empty), skip the 300 ms debounce so
        // pre-filled filters land immediately rather than ~300 ms after
        // the unfiltered firehose flashes through.
        .task(id: filterText) {
            if !firstFilterRun {
                do { try await Task.sleep(nanoseconds: 300_000_000) } catch { return }
            } else {
                firstFilterRun = false
            }
            // Pass the time bounds so the search query honours both
            // the user's chip selection AND any "Investigate in
            // Events" center timestamp. Center timestamp wins when
            // present (a click from a 14:32 alert should narrow to
            // ±30 min around 14:32 regardless of which chip was
            // selected); otherwise the chip's window is used.
            let bounds = computeEventsTimeBounds()
            if filterText.isEmpty {
                await appState.loadEvents(since: bounds.since, until: bounds.until, category: coreCategory)
            } else {
                await appState.loadEvents(filter: filterText, since: bounds.since, until: bounds.until, category: coreCategory)
            }
        }
        // #12: re-query the DB when the range OR category changes — in BOTH
        // the search and non-search paths. Pre-fix the non-search path only
        // re-filtered the already-loaded ~500-row window (via
        // onChange→recomputeFilter), so widening the range — or picking a
        // category — surfaced no additional DB rows and under-represented the
        // window. `eventQueryKey` folds filterCategory into the id so a
        // category change re-queries category-side in the DB, not just
        // in-memory.
        .task(id: eventQueryKey) {
            // When centred (Investigate in Events) the window is fixed to the
            // centre ± half-window regardless of the chip, so a chip change
            // need not re-query (onAppear + the filterText task already load).
            // The in-memory recomputeFilter still applies the category to the
            // small fully-loaded centred window, so no undercount there.
            guard initialCenterTime == nil else { return }
            let bounds = computeEventsTimeBounds()
            if filterText.isEmpty {
                await appState.loadEvents(since: bounds.since, until: bounds.until, category: coreCategory)
            } else {
                await appState.loadEvents(filter: filterText, since: bounds.since, until: bounds.until, category: coreCategory)
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
            identifiedAggregates = Self.identify(aggregateRows)
        }
        // v1.8.0 polish: SQL-side histogram. Re-fetched on time-range,
        // category, or aggregate-mode change — and now also on the live
        // refresh tick (#16), so the chart tracks the live table instead of
        // going stale. Skips work in aggregate mode (the daily aggregate path
        // drives that chart instead). Window + granularity honour an
        // "Investigate in Events" centre time (#2).
        .task(id: histogramInputsKey) {
            guard !isAggregateMode else {
                histogramRows = []
                return
            }
            let window = histogramWindow
            histogramRows = await appState.fetchHistogramBins(
                spanSeconds: window.span,
                stepSeconds: hotHistogramGranularity.stepSeconds,
                endingAt: window.endingAt,
                category: filterCategory.map { MacCrabCore.EventCategory(rawValue: $0.rawValue) } ?? nil
            )
        }
        // v1.7.11: recompute the cached filtered+sorted list only when an
        // input actually changes. Without these, the body's previous use
        // of `timeFilteredEvents` (computed property) re-filtered and
        // re-sorted on every body re-evaluation — and SwiftUI re-evaluates
        // body on every @Published mutation in AppState (heartbeat,
        // agentLineage, etc.), driving 333 Auto Layout constraint
        // allocations/sec via NSTableView rebinds.
        // C4: honour Pause. When paused, drop the live poll's prepended
        // rows on the floor instead of rebuilding the table — the visible
        // set stays frozen. Explicit filter/sort changes below still apply.
        .onReceive(appState.$events) { _ in
            guard !isPaused else { return }
            recomputeFilter()
            // #16: keep the histogram in step with the live table. The
            // histogram task is keyed on this tick, so each live prepend
            // re-queries the SQL bins — but only when the chart is actually
            // shown and in hot-tier mode (the aggregate path has its own path).
            if showHistogram && !isAggregateMode {
                histogramRefreshTick &+= 1
            }
        }
        // Resume: rebuild once from the current events so the frozen table
        // catches up to everything that arrived while paused.
        .onChange(of: isPaused) { paused in
            if !paused { recomputeFilter() }
        }
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
    var triggeredAlerts: [AlertViewModel] = []

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

                // v1.18: surface the alert(s) this event triggered, so the
                // events panel links forward to the alert rather than dead-
                // ending at the raw event.
                if !triggeredAlerts.isEmpty {
                    GroupBox {
                        VStack(alignment: .leading, spacing: 6) {
                            ForEach(triggeredAlerts) { a in
                                HStack(alignment: .top, spacing: 6) {
                                    Circle().fill(a.severityColor)
                                        .frame(width: 8, height: 8).padding(.top, 5)
                                    VStack(alignment: .leading, spacing: 1) {
                                        Text(a.ruleTitle).font(.callout).fontWeight(.medium)
                                        Text(a.ruleId).font(.caption2).foregroundColor(.secondary)
                                    }
                                }
                            }
                            Text(String(localized: "eventDetail.openAlerts", defaultValue: "Open the Alerts workspace for full detail and actions."))
                                .font(.caption2).foregroundColor(.secondary).padding(.top, 2)
                        }.padding(4)
                    } label: {
                        Label("Triggered \(triggeredAlerts.count) alert\(triggeredAlerts.count == 1 ? "" : "s")",
                              systemImage: "bell.badge.fill")
                            .foregroundColor(.orange)
                    }
                }

                GroupBox(String(localized: "eventDetail.process", defaultValue: "Process")) {
                    VStack(alignment: .leading, spacing: 6) {
                        EventDetailRow(label: "Name", value: event.processName)
                        EventDetailRow(label: "PID", value: String(event.pid))
                        // v1.12.6 Wave 9H: surface Wave-2 schema columns
                        // (executable, user, working_directory,
                        // architecture, is_notarized, ai_tool, parent,
                        // process_sha256). Pre-9H these were populated
                        // in events.db but never rendered.
                        if !event.executablePath.isEmpty {
                            EventDetailRow(label: "Path", value: event.executablePath)
                        }
                        if !event.commandLine.isEmpty {
                            EventDetailRow(label: "Command", value: event.commandLine)
                        }
                        if !event.signerType.isEmpty {
                            EventDetailRow(label: "Signer", value: event.signerType)
                        }
                        if let notarized = event.isNotarized {
                            EventDetailRow(label: "Notarized", value: notarized ? "Yes" : "No")
                        }
                        if !event.architecture.isEmpty {
                            EventDetailRow(label: "Arch", value: event.architecture)
                        }
                        if !event.userName.isEmpty {
                            EventDetailRow(label: "User", value: event.userName)
                        }
                        if !event.workingDirectory.isEmpty {
                            EventDetailRow(label: "CWD", value: event.workingDirectory)
                        }
                        if !event.aiTool.isEmpty {
                            EventDetailRow(label: "AI tool", value: event.aiTool)
                        }
                        if !event.parentName.isEmpty {
                            EventDetailRow(label: "Parent", value: event.parentName)
                        }
                        if !event.parentExecutable.isEmpty {
                            EventDetailRow(label: "Parent path", value: event.parentExecutable)
                        }
                        if !event.processSHA256.isEmpty {
                            EventDetailRow(label: "SHA-256", value: event.processSHA256)
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
            // v1.12.6 Wave 9H: widened from 60 → 90 to accommodate
            // new labels added in this wave: "Notarized", "Parent path",
            // "SHA-256". 60 truncated those with an ellipsis.
            Text(label).font(.caption).foregroundColor(.secondary).frame(width: 90, alignment: .trailing)
            Text(value).font(.system(.subheadline, design: .monospaced)).textSelection(.enabled)
        }
    }
}

