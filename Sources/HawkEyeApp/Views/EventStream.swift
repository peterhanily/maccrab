// EventStream.swift
// HawkEyeApp
//
// Live event stream viewer (similar to ProcMon) showing security events
// in a scrollable table with category filtering and pause controls.

import SwiftUI

// MARK: - EventStream

struct EventStream: View {
    @ObservedObject var appState: AppState
    @State private var filterText: String = ""
    @State private var filterCategory: EventCategory? = nil
    @State private var isPaused: Bool = false
    @State private var autoScroll: Bool = true
    @State private var selectedEventID: EventViewModel.ID? = nil

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

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            // Toolbar
            HStack(spacing: 12) {
                Text("Events")
                    .font(.title2)
                    .fontWeight(.bold)

                Text("\(filteredEvents.count)")
                    .font(.caption)
                    .padding(.horizontal, 8)
                    .padding(.vertical, 2)
                    .background(Color.secondary.opacity(0.2))
                    .clipShape(Capsule())

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

                TextField("Filter...", text: $filterText)
                    .textFieldStyle(.roundedBorder)
                    .frame(width: 200)

                Divider()
                    .frame(height: 16)

                Toggle("Auto-scroll", isOn: $autoScroll)
                    .toggleStyle(.checkbox)
                    .font(.caption)

                Button {
                    isPaused.toggle()
                } label: {
                    Image(systemName: isPaused ? "play.fill" : "pause.fill")
                    Text(isPaused ? "Resume" : "Pause")
                }
                .buttonStyle(.bordered)
                .controlSize(.small)
            }
            .padding()

            Divider()

            // Event table
            if filteredEvents.isEmpty {
                VStack(spacing: 12) {
                    Spacer()
                    Image(systemName: "list.bullet.rectangle")
                        .font(.system(size: 48))
                        .foregroundColor(.secondary.opacity(0.5))
                    Text("No events matching current filters")
                        .font(.headline)
                        .foregroundColor(.secondary)
                    if filterCategory != nil || !filterText.isEmpty {
                        Button("Clear Filters") {
                            filterCategory = nil
                            filterText = ""
                        }
                    }
                    Spacer()
                }
                .frame(maxWidth: .infinity)
            } else {
                Table(filteredEvents, selection: $selectedEventID) {
                    TableColumn("Time") { event in
                        Text(event.timeString)
                            .font(.system(.body, design: .monospaced))
                    }
                    .width(min: 60, ideal: 80, max: 100)

                    TableColumn("Action") { event in
                        Text(event.action)
                            .fontWeight(.medium)
                            .foregroundColor(event.actionColor)
                    }
                    .width(min: 60, ideal: 80, max: 100)

                    TableColumn("Category") { event in
                        CategoryBadge(category: event.category)
                    }
                    .width(min: 70, ideal: 90, max: 110)

                    TableColumn("Process") { event in
                        Text("\(event.processName) (\(event.pid))")
                    }
                    .width(min: 120, ideal: 160, max: 220)

                    TableColumn("Detail") { event in
                        Text(event.detail)
                            .lineLimit(1)
                            .help(event.detail)
                    }

                    TableColumn("Signer") { event in
                        SignerBadge(signerType: event.signerType)
                    }
                    .width(min: 60, ideal: 80, max: 100)
                }
            }

            // Status bar
            HStack {
                if isPaused {
                    Image(systemName: "pause.circle.fill")
                        .foregroundColor(.orange)
                    Text("Paused")
                        .foregroundColor(.orange)
                } else {
                    Image(systemName: "circle.fill")
                        .foregroundColor(.green)
                        .font(.system(size: 6))
                    Text("Live")
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
        .task {
            await appState.loadEvents()
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

// MARK: - Preview

#Preview {
    EventStream(appState: AppState())
        .frame(width: 900, height: 600)
}
