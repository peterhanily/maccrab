// TCCTimeline.swift
// MacCrabApp
//
// TCC (Transparency, Consent, and Control) permission view. Three modes:
//   - Timeline (legacy): grants/revocations chronologically
//   - Services (v1.7.1): per-service → list of apps and their current status
//   - Apps (v1.7.1): per-app → list of services and their current status
// Services and Apps modes pull from the daemon's tcc_snapshot.json.

import SwiftUI
import MacCrabCore

// MARK: - TCCTimeline

struct TCCTimeline: View {
    @ObservedObject var appState: AppState
    @State private var filterService: String? = nil
    @State private var filterAllowed: Bool? = nil
    @State private var searchText: String = ""
    /// v1.7.1 view modes.
    enum ViewMode: String, CaseIterable, Identifiable {
        case timeline = "Timeline"
        case services = "Services"
        case apps = "Apps"
        var id: String { rawValue }
    }
    @State private var viewMode: ViewMode = .timeline

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
                Text(String(localized: "tcc.title", defaultValue: "Permissions"))
                    .font(.title2)
                    .fontWeight(.bold)

                Picker("Mode", selection: $viewMode) {
                    ForEach(ViewMode.allCases) { m in
                        Text(m.rawValue).tag(m)
                    }
                }
                .pickerStyle(.segmented)
                .frame(width: 280)

                Text("\(filteredEvents.count)")
                    .font(.caption)
                    .padding(.horizontal, 8)
                    .padding(.vertical, 2)
                    .background(Color.secondary.opacity(0.2))
                    .clipShape(Capsule())

                Spacer()

                // Service filter
                Picker("Service", selection: $filterService) {
                    Text(String(localized: "tcc.allServices", defaultValue: "All Services")).tag(nil as String?)
                    Divider()
                    ForEach(serviceNames, id: \.self) { name in
                        Text(name).tag(name as String?)
                    }
                }
                .frame(width: 180)

                // Allowed/denied filter
                Picker("Status", selection: $filterAllowed) {
                    Text(String(localized: "tcc.all", defaultValue: "All")).tag(nil as Bool?)
                    Text(String(localized: "tcc.granted", defaultValue: "Granted")).tag(true as Bool?)
                    Text(String(localized: "tcc.denied", defaultValue: "Denied")).tag(false as Bool?)
                }
                .frame(width: 120)

                TextField("Search...", text: $searchText)
                    .textFieldStyle(.roundedBorder)
                    .frame(width: 200)
            }
            .padding()

            Divider()

            // v1.7.1: route to the chosen view mode.
            switch viewMode {
            case .services:
                tccMatrix(groupBy: .service)
            case .apps:
                tccMatrix(groupBy: .client)
            case .timeline:
                timelineBody
            }
        }
        .task {
            await appState.loadTCCEvents()
        }
    }

    // MARK: - Timeline body (legacy mode)

    @ViewBuilder
    private var timelineBody: some View {
        Group {
            if filteredEvents.isEmpty {
                VStack(spacing: 12) {
                    Spacer()
                    Image(systemName: "lock.shield")
                        .font(.system(size: 48))
                        .foregroundColor(.secondary.opacity(0.5))
                        .accessibilityHidden(true)
                    Text(appState.tccEvents.isEmpty
                        ? String(localized: "tcc.emptyDefault", defaultValue: "No permission changes detected yet")
                        : String(localized: "tcc.noMatch", defaultValue: "No TCC events matching current filters"))
                        .font(.headline)
                        .foregroundColor(.secondary)
                    if filterService != nil || filterAllowed != nil || !searchText.isEmpty {
                        Button(String(localized: "tcc.clearFilters", defaultValue: "Clear Filters")) {
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
                    .accessibilityHidden(true)
                Text("\(granted) \(String(localized: "tcc.granted", defaultValue: "granted"))")
                    .font(.caption)
                    .foregroundColor(.secondary)

                Image(systemName: "xmark.circle.fill")
                    .foregroundColor(.red)
                    .font(.caption)
                    .padding(.leading, 8)
                    .accessibilityHidden(true)
                Text("\(denied) \(String(localized: "tcc.denied", defaultValue: "denied"))")
                    .font(.caption)
                    .foregroundColor(.secondary)

                Spacer()

                Text("\(appState.tccEvents.count) \(String(localized: "tcc.totalEventsLabel", defaultValue: "total events"))")
                    .font(.caption)
                    .foregroundColor(.secondary)
            }
            .padding(.horizontal)
            .padding(.vertical, 6)
            .background(.bar)
        }
    }

    // MARK: - Matrix views (v1.7.1)

    private enum GroupAxis { case service, client }

    private func friendlyService(_ raw: String) -> String {
        // Same simple mapping the timeline already uses, abbreviated.
        let trimmed = raw.replacingOccurrences(of: "kTCCService", with: "")
        return trimmed.isEmpty ? raw : trimmed
    }

    @ViewBuilder
    private func tccMatrix(groupBy axis: GroupAxis) -> some View {
        let entries = filteredSnapshotEntries
        if entries.isEmpty {
            VStack(spacing: 12) {
                Spacer()
                Image(systemName: "lock.shield")
                    .font(.system(size: 48))
                    .foregroundColor(.secondary.opacity(0.5))
                Text(appState.tccSnapshotEntries.isEmpty
                     ? "Permission matrix not yet available — wait for the next daemon heartbeat tick."
                     : "No entries match current filters.")
                    .font(.headline).foregroundColor(.secondary)
                    .multilineTextAlignment(.center)
                Spacer()
            }
            .frame(maxWidth: .infinity)
        } else {
            let groups = Dictionary(grouping: entries) { entry -> String in
                axis == .service ? friendlyService(entry.service) : entry.client
            }
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    ForEach(groups.keys.sorted(), id: \.self) { key in
                        if let rows = groups[key] {
                            VStack(alignment: .leading, spacing: 6) {
                                HStack {
                                    Image(systemName: axis == .service ? "lock.shield" : "app.badge")
                                        .foregroundColor(.secondary)
                                    Text(key).font(.headline)
                                    Text("(\(rows.count))")
                                        .font(.caption).foregroundColor(.secondary)
                                    Spacer()
                                }
                                ForEach(rows.sorted { lhs, rhs in
                                    if lhs.authValue != rhs.authValue { return lhs.authValue > rhs.authValue }
                                    return (axis == .service ? lhs.client : friendlyService(lhs.service))
                                        < (axis == .service ? rhs.client : friendlyService(rhs.service))
                                }, id: \.self) { row in
                                    HStack {
                                        Image(systemName: row.authValue == 2 ? "checkmark.circle.fill" :
                                                            row.authValue == 0 ? "xmark.circle.fill" : "questionmark.circle.fill")
                                            .foregroundColor(row.authValue == 2 ? .green :
                                                              row.authValue == 0 ? .red : .secondary)
                                        Text(axis == .service ? row.client : friendlyService(row.service))
                                            .font(.subheadline)
                                        Spacer()
                                        Text(row.source)
                                            .font(.caption)
                                            .foregroundColor(.secondary)
                                        Text(Date(timeIntervalSince1970: row.lastModified)
                                                .formatted(.relative(presentation: .named)))
                                            .font(.caption)
                                            .foregroundColor(.secondary)
                                    }
                                    .padding(.horizontal, 8)
                                    .padding(.vertical, 4)
                                    .background(Color.secondary.opacity(0.05))
                                    .clipShape(RoundedRectangle(cornerRadius: 4))
                                }
                            }
                            .padding(.horizontal)
                        }
                    }
                }
                .padding(.vertical, 12)
            }
        }
    }

    private var filteredSnapshotEntries: [TCCMonitor.PublicEntry] {
        var rows = appState.tccSnapshotEntries
        if let allowed = filterAllowed {
            rows = rows.filter { ($0.authValue == 2) == allowed }
        }
        if let svc = filterService {
            rows = rows.filter { friendlyService($0.service) == svc }
        }
        if !searchText.isEmpty {
            let q = searchText.lowercased()
            rows = rows.filter {
                $0.service.lowercased().contains(q)
                    || $0.client.lowercased().contains(q)
                    || friendlyService($0.service).lowercased().contains(q)
            }
        }
        return rows
    }
}

// MARK: - TCCEventRow

/// A single row in the TCC timeline.
private struct TCCEventRow: View {
    let event: TCCEventViewModel

    var body: some View {
        HStack(spacing: 12) {
            // Grant/deny indicator
            HStack(spacing: 4) {
                Image(systemName: event.allowed ? "checkmark.circle.fill" : "xmark.circle.fill")
                    .foregroundColor(event.allowed ? .green : .red)
                    .font(.title3)
                Text(event.allowed
                    ? String(localized: "tcc.granted", defaultValue: "Granted")
                    : String(localized: "tcc.denied", defaultValue: "Denied"))
                    .font(.caption2)
                    .foregroundColor(event.allowed ? .green : .red)
            }
            .accessibilityLabel(event.allowed ? "Permission granted" : "Permission denied")

            // Service and client info
            VStack(alignment: .leading, spacing: 3) {
                HStack {
                    Text(event.friendlyServiceName)
                        .font(.headline)
                    Text(event.allowed
                        ? String(localized: "tcc.granted", defaultValue: "Granted")
                        : String(localized: "tcc.denied", defaultValue: "Denied"))
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
        .accessibilityElement(children: .combine)
    }
}

