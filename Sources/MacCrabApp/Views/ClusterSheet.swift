// ClusterSheet.swift
// MacCrabApp
//
// v1.6.8: a modal surface for the AlertClusterService that ships in
// v1.6.6. The triage workflow is: open the sheet, see N alerts
// collapsed into M clusters by rule+process fingerprint, click a
// cluster to expand its members, optionally click "Suppress all in
// cluster" to bulk-silence. The sheet is opened from AlertDashboard
// via a toolbar button; the dashboard keeps its existing per-alert
// list unchanged.

import SwiftUI
import MacCrabCore

struct ClusterSheet: View {
    @ObservedObject var appState: AppState
    @Environment(\.dismiss) var dismiss

    @State private var clusters: [AlertCluster] = []
    @State private var expandedClusterId: String?
    @State private var isRefreshing = false

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header
            Divider()
            if clusters.isEmpty {
                emptyState
            } else {
                clusterList
            }
            Divider()
            footer
        }
        .frame(width: 640, height: 520)
        .task { await refresh() }
    }

    // MARK: Sections

    private var header: some View {
        HStack {
            Image(systemName: "square.stack.3d.up")
                .font(.title3)
                .foregroundColor(.accentColor)
            VStack(alignment: .leading) {
                Text("Alert Clusters")
                    .font(.headline)
                Text("\(alertCount) alerts \u{2022} \(clusters.count) clusters")
                    .font(.caption)
                    .foregroundColor(.secondary)
            }
            Spacer()
            Button {
                Task { await refresh() }
            } label: {
                Image(systemName: isRefreshing ? "hourglass" : "arrow.clockwise")
            }
            .disabled(isRefreshing)
            .buttonStyle(.borderless)
            .help("Re-cluster the current alert list")
            Button("Done") { dismiss() }
                .controlSize(.small)
        }
        .padding()
    }

    @ViewBuilder
    private var emptyState: some View {
        VStack(spacing: 10) {
            Image(systemName: "rectangle.stack.badge.minus")
                .font(.largeTitle)
                .foregroundColor(.secondary.opacity(0.5))
            Text("No clusters to display")
                .font(.subheadline)
            Text("Open some alerts into the dashboard first — clustering groups alerts that share a rule ID and process name.")
                .font(.caption)
                .foregroundColor(.secondary)
                .multilineTextAlignment(.center)
                .frame(maxWidth: 420)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private var clusterList: some View {
        ScrollView {
            VStack(spacing: 0) {
                ForEach(clusters) { cluster in
                    ClusterRow(
                        cluster: cluster,
                        isExpanded: expandedClusterId == cluster.id,
                        memberAlerts: members(for: cluster),
                        onToggle: { toggleExpansion(cluster.id) },
                        onSuppressAll: { Task { await suppressAllInCluster(cluster) } }
                    )
                    Divider()
                }
            }
        }
    }

    private var footer: some View {
        HStack {
            Text("Clustering groups alerts by rule_id + process_name. Click a row to expand, or Suppress to silence every alert in the cluster.")
                .font(.caption2)
                .foregroundColor(.secondary)
                .lineLimit(2)
            Spacer()
        }
        .padding(.horizontal)
        .padding(.vertical, 6)
    }

    // MARK: Data

    private var alertCount: Int {
        clusters.reduce(0) { $0 + $1.size }
    }

    private func toggleExpansion(_ id: String) {
        withAnimation(.easeInOut(duration: 0.15)) {
            expandedClusterId = (expandedClusterId == id) ? nil : id
        }
    }

    private func refresh() async {
        await MainActor.run { isRefreshing = true }
        defer { Task { @MainActor in isRefreshing = false } }

        // Build ephemeral Alert models from the dashboard's cached
        // AlertViewModels. The UI layer's `Severity` enum mirrors the
        // core one but isn't the same type — convert by rawValue.
        let alerts: [MacCrabCore.Alert] = appState.dashboardAlerts
            .filter { !$0.suppressed && !appState.suppressedIDs.contains($0.id) }
            .map { vm in
            MacCrabCore.Alert(
                id: vm.id,
                timestamp: vm.timestamp,
                ruleId: vm.ruleId,
                ruleTitle: vm.ruleTitle,
                severity: MacCrabCore.Severity(rawValue: vm.severity.rawValue) ?? .low,
                eventId: vm.eventId,
                processPath: vm.processPath.isEmpty ? nil : vm.processPath,
                processName: vm.processName.isEmpty ? nil : vm.processName,
                description: vm.description,
                mitreTactics: nil,
                mitreTechniques: vm.mitreTechniques.isEmpty ? nil : vm.mitreTechniques,
                suppressed: vm.suppressed
            )
        }

        let svc = AlertClusterService()
        let result = await svc.cluster(alerts: alerts)
        await MainActor.run { self.clusters = result }
    }

    private func members(for cluster: AlertCluster) -> [AlertViewModel] {
        let ids = Set(cluster.memberAlertIds)
        return appState.dashboardAlerts.filter { ids.contains($0.id) }
    }

    private func suppressAllInCluster(_ cluster: AlertCluster) async {
        let ids = Set(cluster.memberAlertIds)
        await appState.suppressAlerts(ids)
        await refresh()
    }
}

// MARK: - Severity mapping helpers

/// ClusterSheet receives `MacCrabCore.Severity` (not the UI layer's
/// local mirror), so we can't use the app's `.color` / `.sfSymbol`
/// extensions directly. These helpers provide the same palette the
/// rest of the dashboard uses.
private func clusterSeverityColor(_ s: MacCrabCore.Severity) -> Color {
    switch s {
    case .informational: return .secondary
    case .low:           return .blue
    case .medium:        return Color(red: 0.67, green: 0.37, blue: 0.0)
    case .high:          return .orange
    case .critical:      return .red
    }
}

private func clusterSeveritySymbol(_ s: MacCrabCore.Severity) -> String {
    switch s {
    case .informational: return "info.circle.fill"
    case .low:           return "minus.circle.fill"
    case .medium:        return "exclamationmark.triangle.fill"
    case .high:          return "exclamationmark.circle.fill"
    case .critical:      return "flame.fill"
    }
}

// MARK: - ClusterRow

private struct ClusterRow: View {
    let cluster: AlertCluster
    let isExpanded: Bool
    let memberAlerts: [AlertViewModel]
    let onToggle: () -> Void
    let onSuppressAll: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 10) {
                Image(systemName: clusterSeveritySymbol(cluster.severity))
                    .foregroundColor(clusterSeverityColor(cluster.severity))
                    .frame(width: 20)
                VStack(alignment: .leading, spacing: 2) {
                    Text(cluster.ruleTitle)
                        .font(.subheadline).fontWeight(.medium)
                        .lineLimit(1)
                    HStack(spacing: 6) {
                        Text(cluster.processName)
                            .font(.system(.caption, design: .monospaced))
                            .foregroundColor(.secondary)
                        if !cluster.tactics.isEmpty {
                            Text("\u{2022}")
                                .font(.caption2)
                                .foregroundColor(.secondary)
                            Text(cluster.tactics.sorted()
                                    .map { $0.replacingOccurrences(of: "attack.", with: "") }
                                    .joined(separator: ", "))
                                .font(.caption2)
                                .foregroundColor(.secondary)
                                .lineLimit(1)
                        }
                    }
                }
                Spacer()
                Text("\(cluster.size)")
                    .font(.caption).fontWeight(.semibold)
                    .padding(.horizontal, 8).padding(.vertical, 3)
                    .background(clusterSeverityColor(cluster.severity).opacity(0.15))
                    .foregroundColor(clusterSeverityColor(cluster.severity))
                    .clipShape(Capsule())
                Image(systemName: isExpanded ? "chevron.up" : "chevron.down")
                    .font(.caption).foregroundColor(.secondary)
            }
            .padding(.horizontal)
            .padding(.vertical, 10)
            .contentShape(Rectangle())
            .onTapGesture { onToggle() }

            if isExpanded {
                VStack(alignment: .leading, spacing: 4) {
                    ForEach(memberAlerts.prefix(20), id: \.id) { alert in
                        HStack(spacing: 8) {
                            Image(systemName: alert.severity.sfSymbol)
                                .font(.caption2)
                                .foregroundColor(alert.severityColor)
                                .frame(width: 12)
                            Text(alert.timeAgoString)
                                .font(.caption2)
                                .foregroundColor(.secondary)
                                .frame(width: 80, alignment: .leading)
                            if !alert.description.isEmpty {
                                Text(alert.description)
                                    .font(.caption)
                                    .lineLimit(1)
                            } else {
                                Text(alert.ruleTitle)
                                    .font(.caption)
                                    .foregroundColor(.secondary)
                            }
                            Spacer()
                        }
                    }
                    if memberAlerts.count > 20 {
                        Text("+ \(memberAlerts.count - 20) more alerts")
                            .font(.caption2).foregroundColor(.secondary)
                    }
                    HStack {
                        Spacer()
                        Button(role: .destructive) {
                            onSuppressAll()
                        } label: {
                            Label("Suppress all in cluster (\(cluster.size))", systemImage: "eye.slash")
                                .font(.caption)
                        }
                        .controlSize(.small)
                    }
                }
                .padding(.horizontal)
                .padding(.vertical, 8)
                .background(Color.accentColor.opacity(0.04))
            }
        }
    }
}
