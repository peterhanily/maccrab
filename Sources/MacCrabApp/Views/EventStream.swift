// EventStream.swift
// MacCrabApp
//
// Live event stream viewer (similar to ProcMon) showing security events
// in a scrollable table with category filtering and pause controls.

import SwiftUI

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

    /// Events filtered by the current category and text filters.
    private var filteredEvents: [EventViewModel] {
        var results = appState.events

        // Filter by category
        if let category = filterCategory {
            results = results.filter { $0.category == category }
        }

        // Filter by text
        if !filterText.isEmpty {
            let query = filterText.lowercased()
            results = results.filter { event in
                event.action.lowercased().contains(query)
                    || event.processName.lowercased().contains(query)
                    || event.detail.lowercased().contains(query)
                    || event.signerType.lowercased().contains(query)
                    || String(event.pid).contains(query)
            }
        }

        return results
    }

    /// Events filtered by both category/text and time range, then sorted.
    private var timeFilteredEvents: [EventViewModel] {
        var results = filteredEvents
        if let seconds = timeRange.seconds {
            let cutoff = Date().addingTimeInterval(-seconds)
            results = results.filter { $0.timestamp >= cutoff }
        }
        return results.sorted(using: sortOrder)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            // Toolbar
            HStack(spacing: 12) {
                Text(String(localized: "events.title", defaultValue: "Events"))
                    .font(.title2)
                    .fontWeight(.bold)

                Text("\(timeFilteredEvents.count)")
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

            // Event table
            if timeFilteredEvents.isEmpty {
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
                    Table(timeFilteredEvents, selection: $selectedEventID, sortOrder: $sortOrder) {
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
                       let event = timeFilteredEvents.first(where: { $0.id == selectedID }) {
                        Divider()
                        EventDetailPanel(event: event)
                            .frame(minWidth: 280, idealWidth: 350, maxWidth: 450)
                            .transition(reduceMotion ? .opacity : .move(edge: .trailing))
                    }
                }
                .animation(reduceMotion ? nil : .easeInOut(duration: 0.2), value: selectedEventID)
            }

            // Status bar
            HStack {
                if isPaused {
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
            Task { await appState.loadEvents() }
        }
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

