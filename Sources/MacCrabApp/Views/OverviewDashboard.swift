// OverviewDashboard.swift
// MacCrabApp
//
// The overview homepage — the first thing users see.
// Shows call-to-action banners, stats, severity distribution,
// recent alerts, and system health at a glance.

import SwiftUI

struct OverviewDashboard: View {
    @ObservedObject var appState: AppState

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                // === Call to Action Banner ===
                if criticalCount > 0 {
                    HStack(spacing: 12) {
                        Image(systemName: "exclamationmark.triangle.fill")
                            .font(.title2)
                            .foregroundColor(.white)
                        VStack(alignment: .leading) {
                            Text("\(criticalCount) critical alert\(criticalCount == 1 ? "" : "s") need\(criticalCount == 1 ? "s" : "") investigation")
                                .font(.headline)
                                .foregroundColor(.white)
                            Text("Review immediately in the Alerts section")
                                .font(.caption)
                                .foregroundColor(.white.opacity(0.8))
                        }
                        Spacer()
                    }
                    .padding()
                    .background(Color.red)
                    .cornerRadius(12)
                    .padding(.horizontal)
                } else if highCount > 0 {
                    HStack(spacing: 12) {
                        Image(systemName: "exclamationmark.circle.fill")
                            .font(.title2)
                            .foregroundColor(.white)
                        VStack(alignment: .leading) {
                            Text("\(highCount) high-severity alert\(highCount == 1 ? "" : "s") to review")
                                .font(.headline)
                                .foregroundColor(.white)
                        }
                        Spacer()
                    }
                    .padding()
                    .background(Color.orange)
                    .cornerRadius(12)
                    .padding(.horizontal)
                } else {
                    HStack(spacing: 12) {
                        Image(systemName: "checkmark.shield.fill")
                            .font(.title2)
                            .foregroundColor(.white)
                        VStack(alignment: .leading) {
                            Text("All clear — no critical alerts")
                                .font(.headline)
                                .foregroundColor(.white)
                            Text("\(appState.eventsPerSecond) events/sec monitored")
                                .font(.caption)
                                .foregroundColor(.white.opacity(0.8))
                        }
                        Spacer()
                    }
                    .padding()
                    .background(Color.green)
                    .cornerRadius(12)
                    .padding(.horizontal)
                }

                // === Stats Row ===
                HStack(spacing: 16) {
                    StatCard(title: "Alerts", value: "\(appState.totalAlerts)", icon: "exclamationmark.triangle", color: .orange)
                    StatCard(title: "Rules", value: "\(appState.rulesLoaded)", icon: "shield.checkered", color: .blue)
                    StatCard(title: "Events/sec", value: "\(appState.eventsPerSecond)", icon: "waveform.path.ecg", color: .green)
                    StatCard(title: "Connected", value: appState.isConnected ? "Yes" : "No", icon: appState.isConnected ? "checkmark.circle" : "xmark.circle", color: appState.isConnected ? .green : .red)
                }
                .padding(.horizontal)

                // === Severity Distribution ===
                GroupBox("Alert Severity") {
                    HStack(spacing: 2) {
                        SeverityBar(label: "Critical", count: criticalCount, color: .red, total: max(appState.totalAlerts, 1))
                        SeverityBar(label: "High", count: highCount, color: .orange, total: max(appState.totalAlerts, 1))
                        SeverityBar(label: "Medium", count: mediumCount, color: .yellow, total: max(appState.totalAlerts, 1))
                        SeverityBar(label: "Low", count: lowCount, color: .blue, total: max(appState.totalAlerts, 1))
                    }
                    .frame(height: 32)
                    .clipShape(RoundedRectangle(cornerRadius: 6))
                    .padding(4)
                }
                .padding(.horizontal)

                HStack(alignment: .top, spacing: 16) {
                    // === Recent Alerts ===
                    GroupBox("Recent Alerts") {
                        if appState.recentAlerts.isEmpty {
                            Text("No recent alerts")
                                .font(.caption)
                                .foregroundColor(.secondary)
                                .frame(maxWidth: .infinity)
                                .padding()
                        } else {
                            VStack(alignment: .leading, spacing: 6) {
                                ForEach(appState.recentAlerts.prefix(5), id: \.id) { alert in
                                    HStack(spacing: 8) {
                                        Circle()
                                            .fill(alert.severityColor)
                                            .frame(width: 8, height: 8)
                                        Text(alert.ruleTitle)
                                            .font(.caption)
                                            .lineLimit(1)
                                        Spacer()
                                        Text(alert.timeAgoString)
                                            .font(.caption2)
                                            .foregroundColor(.secondary)
                                    }
                                }
                            }
                            .padding(4)
                        }
                    }

                    // === System Health ===
                    GroupBox("System Health") {
                        VStack(alignment: .leading, spacing: 6) {
                            HealthRow(label: "Daemon", status: appState.isConnected, detail: appState.isConnected ? "Active" : "Not connected")
                            HealthRow(label: "Rules", status: appState.rulesLoaded > 0, detail: "\(appState.rulesLoaded) loaded")
                            HealthRow(label: "Events", status: appState.eventsPerSecond > 0, detail: "\(appState.eventsPerSecond)/sec")
                        }
                        .padding(4)
                    }
                }
                .padding(.horizontal)

                Spacer()
            }
            .padding(.top)
        }
        .navigationTitle("Overview")
    }

    // Computed properties
    private var criticalCount: Int {
        appState.dashboardAlerts.filter { $0.severity == .critical && !$0.suppressed }.count
    }
    private var highCount: Int {
        appState.dashboardAlerts.filter { $0.severity == .high && !$0.suppressed }.count
    }
    private var mediumCount: Int {
        appState.dashboardAlerts.filter { $0.severity == .medium && !$0.suppressed }.count
    }
    private var lowCount: Int {
        appState.dashboardAlerts.filter { $0.severity == .low && !$0.suppressed }.count
    }
}

// MARK: - Supporting Views

struct StatCard: View {
    let title: String
    let value: String
    let icon: String
    let color: Color

    var body: some View {
        GroupBox {
            VStack(spacing: 4) {
                Image(systemName: icon)
                    .font(.title3)
                    .foregroundColor(color)
                Text(value)
                    .font(.system(.title2, design: .rounded, weight: .bold))
                Text(title)
                    .font(.caption2)
                    .foregroundColor(.secondary)
            }
            .frame(maxWidth: .infinity)
            .padding(.vertical, 4)
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(title): \(value)")
    }
}

struct SeverityBar: View {
    let label: String
    let count: Int
    let color: Color
    let total: Int

    var body: some View {
        let fraction = CGFloat(count) / CGFloat(total)
        if count > 0 {
            Rectangle()
                .fill(color)
                .frame(maxWidth: .infinity)
                .scaleEffect(x: max(fraction, 0.05), y: 1, anchor: .leading)
                .overlay(
                    Text("\(count)")
                        .font(.system(.caption2, weight: .bold))
                        .foregroundColor(.white)
                )
        }
    }
}

struct HealthRow: View {
    let label: String
    let status: Bool
    let detail: String

    var body: some View {
        HStack(spacing: 8) {
            Image(systemName: status ? "checkmark.circle.fill" : "xmark.circle.fill")
                .foregroundColor(status ? .green : .red)
                .font(.caption)
            Text(label)
                .font(.caption)
                .fontWeight(.medium)
            Spacer()
            Text(detail)
                .font(.caption)
                .foregroundColor(.secondary)
        }
    }
}
