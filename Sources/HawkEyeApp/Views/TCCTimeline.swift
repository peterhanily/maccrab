// TCCTimeline.swift
// HawkEyeApp
//
// TCC (Transparency, Consent, and Control) permission timeline view.
// Shows grants and revocations of macOS protected resources over time.

import SwiftUI

// MARK: - TCCTimeline

struct TCCTimeline: View {
    @ObservedObject var appState: AppState
    @State private var filterService: String? = nil
    @State private var filterAllowed: Bool? = nil
    @State private var searchText: String = ""

    /// All unique service names from the loaded TCC events.
    private var serviceNames: [String] {
        let names = Set(appState.tccEvents.map { $0.friendlyServiceName })
        return names.sorted()
    }

    /// TCC events filtered by current service, allowed status, and search text.
    private var filteredEvents: [TCCEventViewModel] {
        var results = appState.tccEvents

        // Filter by service
        if let service = filterService {
            results = results.filter { $0.friendlyServiceName == service }
        }

        // Filter by allowed/denied
        if let allowed = filterAllowed {
            results = results.filter { $0.allowed == allowed }
        }

        // Filter by search text
        if !searchText.isEmpty {
            let query = searchText.lowercased()
            results = results.filter { event in
                event.serviceName.lowercased().contains(query)
                    || event.clientName.lowercased().contains(query)
                    || event.clientPath.lowercased().contains(query)
                    || event.friendlyServiceName.lowercased().contains(query)
                    || event.authReason.lowercased().contains(query)
            }
        }

        return results
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            // Header
            HStack(spacing: 12) {
                Text("TCC Permission Timeline")
                    .font(.title2)
                    .fontWeight(.bold)

                Text("\(filteredEvents.count)")
                    .font(.caption)
                    .padding(.horizontal, 8)
                    .padding(.vertical, 2)
                    .background(Color.secondary.opacity(0.2))
                    .clipShape(Capsule())

                Spacer()

                // Service filter
                Picker("Service", selection: $filterService) {
                    Text("All Services").tag(nil as String?)
                    Divider()
                    ForEach(serviceNames, id: \.self) { name in
                        Text(name).tag(name as String?)
                    }
                }
                .frame(width: 180)

                // Allowed/denied filter
                Picker("Status", selection: $filterAllowed) {
                    Text("All").tag(nil as Bool?)
                    Text("Granted").tag(true as Bool?)
                    Text("Denied").tag(false as Bool?)
                }
                .frame(width: 120)

                TextField("Search...", text: $searchText)
                    .textFieldStyle(.roundedBorder)
                    .frame(width: 200)
            }
            .padding()

            Divider()

            // TCC event list
            if filteredEvents.isEmpty {
                VStack(spacing: 12) {
                    Spacer()
                    Image(systemName: "lock.shield")
                        .font(.system(size: 48))
                        .foregroundColor(.secondary.opacity(0.5))
                    Text("No TCC events matching current filters")
                        .font(.headline)
                        .foregroundColor(.secondary)
                    if filterService != nil || filterAllowed != nil || !searchText.isEmpty {
                        Button("Clear Filters") {
                            filterService = nil
                            filterAllowed = nil
                            searchText = ""
                        }
                    }
                    Spacer()
                }
                .frame(maxWidth: .infinity)
            } else {
                List(filteredEvents) { event in
                    TCCEventRow(event: event)
                }
            }

            // Summary bar
            HStack {
                let granted = appState.tccEvents.filter(\.allowed).count
                let denied = appState.tccEvents.filter { !$0.allowed }.count

                Image(systemName: "checkmark.circle.fill")
                    .foregroundColor(.green)
                    .font(.caption)
                Text("\(granted) granted")
                    .font(.caption)
                    .foregroundColor(.secondary)

                Image(systemName: "xmark.circle.fill")
                    .foregroundColor(.red)
                    .font(.caption)
                    .padding(.leading, 8)
                Text("\(denied) denied")
                    .font(.caption)
                    .foregroundColor(.secondary)

                Spacer()

                Text("\(appState.tccEvents.count) total events")
                    .font(.caption)
                    .foregroundColor(.secondary)
            }
            .padding(.horizontal)
            .padding(.vertical, 6)
            .background(.bar)
        }
        .task {
            await appState.loadTCCEvents()
        }
    }
}

// MARK: - TCCEventRow

/// A single row in the TCC timeline.
private struct TCCEventRow: View {
    let event: TCCEventViewModel

    var body: some View {
        HStack(spacing: 12) {
            // Grant/deny indicator
            Image(systemName: event.allowed ? "checkmark.circle.fill" : "xmark.circle.fill")
                .foregroundColor(event.allowed ? .green : .red)
                .font(.title3)

            // Service and client info
            VStack(alignment: .leading, spacing: 3) {
                HStack {
                    Text(event.friendlyServiceName)
                        .font(.headline)
                    Text(event.allowed ? "Granted" : "Denied")
                        .font(.caption)
                        .fontWeight(.semibold)
                        .padding(.horizontal, 6)
                        .padding(.vertical, 2)
                        .background(event.allowed ? Color.green.opacity(0.15) : Color.red.opacity(0.15))
                        .foregroundColor(event.allowed ? .green : .red)
                        .clipShape(Capsule())
                }

                Text(event.clientName)
                    .font(.subheadline)
                    .foregroundColor(.secondary)

                HStack(spacing: 16) {
                    Label(event.clientPath, systemImage: "folder")
                        .font(.caption)
                        .foregroundColor(.secondary)
                        .lineLimit(1)

                    Label(event.authReason.replacingOccurrences(of: "_", with: " ").capitalized,
                          systemImage: "info.circle")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
            }

            Spacer()

            // Timestamp
            Text(event.timeString)
                .font(.caption)
                .foregroundColor(.secondary)
        }
        .padding(.vertical, 6)
    }
}

// MARK: - Preview

#Preview {
    TCCTimeline(appState: AppState())
        .frame(width: 900, height: 600)
}
