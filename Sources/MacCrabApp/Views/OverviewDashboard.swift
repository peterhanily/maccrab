// OverviewDashboard.swift
// MacCrabApp
//
// The overview homepage — the first thing users see.
// Shows call-to-action banners, stats, severity distribution,
// recent alerts, and system health at a glance.

import SwiftUI

struct OverviewDashboard: View {
    @ObservedObject var appState: AppState
    @Binding var selectedSection: MainView.SidebarSection?
    @AppStorage("prevention.dnsSinkhole") private var dnsSinkholeEnabled = false
    @AppStorage("prevention.networkBlocker") private var networkBlockerEnabled = false
    @AppStorage("prevention.persistenceGuard") private var persistenceGuardEnabled = false

    // Muted colors for a professional look
    private let criticalColor = Color(red: 0.75, green: 0.22, blue: 0.22)
    private let highColor = Color(red: 0.80, green: 0.52, blue: 0.20)
    private let allClearColor = Color(red: 0.25, green: 0.60, blue: 0.35)

    private var preventionActive: Bool {
        dnsSinkholeEnabled || networkBlockerEnabled || persistenceGuardEnabled
    }

    var body: some View {
        ScrollView {
            if !appState.isConnected && appState.rulesLoaded == 0 {
                VStack(spacing: 12) {
                    ProgressView()
                        .scaleEffect(1.5)
                    Text("Connecting to MacCrab daemon...")
                        .font(.headline)
                        .foregroundColor(.secondary)
                    Text("Start the daemon: sudo maccrabd")
                        .font(.subheadline)
                        .foregroundColor(.secondary)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
                .padding(40)
            } else {
                VStack(alignment: .leading, spacing: 20) {
                    // === Call to Action Banner (clickable → navigates to Alerts) ===
                    Button { selectedSection = .alerts } label: {
                        HStack(spacing: 12) {
                            Image(systemName: criticalCount > 0 ? "exclamationmark.triangle.fill" : highCount > 0 ? "exclamationmark.circle.fill" : "checkmark.shield.fill")
                                .font(.title)
                                .foregroundColor(.white)
                            VStack(alignment: .leading, spacing: 4) {
                                if criticalCount > 0 {
                                    Text("\(criticalCount) critical alert\(criticalCount == 1 ? "" : "s") need\(criticalCount == 1 ? "s" : "") investigation")
                                        .font(.system(.body, weight: .semibold))
                                        .foregroundColor(.white)
                                    Text("Click to review in Alerts")
                                        .font(.subheadline)
                                        .foregroundColor(.white.opacity(0.8))
                                } else if highCount > 0 {
                                    Text("\(highCount) high-severity alert\(highCount == 1 ? "" : "s") to review")
                                        .font(.system(.body, weight: .semibold))
                                        .foregroundColor(.white)
                                    Text("Click to review in Alerts")
                                        .font(.subheadline)
                                        .foregroundColor(.white.opacity(0.8))
                                } else {
                                    Text("All clear — no critical alerts")
                                        .font(.system(.body, weight: .semibold))
                                        .foregroundColor(.white)
                                    Text("\(appState.eventsPerSecond) events/sec monitored")
                                        .font(.subheadline)
                                        .foregroundColor(.white.opacity(0.8))
                                }
                            }
                            Spacer()
                            Image(systemName: "chevron.right")
                                .foregroundColor(.white.opacity(0.6))
                        }
                        .padding()
                        .background(criticalCount > 0 ? criticalColor : highCount > 0 ? highColor : allClearColor)
                        .cornerRadius(12)
                    }
                    .buttonStyle(.plain)
                    .padding(.horizontal)

                    // === Stats Row ===
                    HStack(spacing: 16) {
                        StatCard(title: "Alerts", value: "\(appState.totalAlerts)", icon: "exclamationmark.triangle", color: .orange)
                        StatCard(title: "Rules", value: "\(appState.rulesLoaded)", icon: "shield.checkered", color: .blue)
                        StatCard(title: "Events/sec", value: "\(appState.eventsPerSecond)", icon: "waveform.path.ecg", color: .green)
                        StatCard(title: "Connected", value: appState.isConnected ? "Yes" : "No", icon: appState.isConnected ? "checkmark.circle" : "xmark.circle", color: appState.isConnected ? .green : .red)
                        StatCard(title: "Security", value: "\u{2014}", icon: "shield.checkered", color: .purple)
                    }
                    .padding(.horizontal)

                    // === Prevention Status ===
                    HStack(spacing: 8) {
                        Image(systemName: "hand.raised.fill")
                            .foregroundColor(preventionActive ? .green : .secondary)
                        Text(preventionActive ? "Prevention Active" : "Prevention Standby")
                            .font(.subheadline)
                            .foregroundColor(preventionActive ? .primary : .secondary)
                        Spacer()
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
                                    .font(.subheadline)
                                    .foregroundColor(.secondary)
                                    .frame(maxWidth: .infinity)
                                    .padding()
                            } else {
                                VStack(alignment: .leading, spacing: 8) {
                                    ForEach(appState.recentAlerts.prefix(5), id: \.id) { alert in
                                        Button { selectedSection = .alerts } label: {
                                            HStack(spacing: 8) {
                                                Circle()
                                                    .fill(alert.severityColor)
                                                    .frame(width: 8, height: 8)
                                                Text(alert.ruleTitle)
                                                    .font(.subheadline)
                                                    .lineLimit(1)
                                                Spacer()
                                                Text(alert.timeAgoString)
                                                    .font(.caption)
                                                    .foregroundColor(.secondary)
                                                Image(systemName: "chevron.right")
                                                    .font(.caption2)
                                                    .foregroundColor(.secondary)
                                            }
                                        }
                                        .buttonStyle(.plain)
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
        }
        .navigationTitle("Overview")
    }

    // Computed properties — must check BOTH .suppressed flag AND pattern suppression
    private func isEffectivelySuppressed(_ alert: AlertViewModel) -> Bool {
        alert.suppressed || appState.isPatternSuppressed(alert)
    }

    private var criticalCount: Int {
        appState.dashboardAlerts.filter { $0.severity == .critical && !isEffectivelySuppressed($0) }.count
    }
    private var highCount: Int {
        appState.dashboardAlerts.filter { $0.severity == .high && !isEffectivelySuppressed($0) }.count
    }
    private var mediumCount: Int {
        appState.dashboardAlerts.filter { $0.severity == .medium && !isEffectivelySuppressed($0) }.count
    }
    private var lowCount: Int {
        appState.dashboardAlerts.filter { $0.severity == .low && !isEffectivelySuppressed($0) }.count
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
            VStack(spacing: 6) {
                Image(systemName: icon)
                    .font(.title2)
                    .foregroundColor(color)
                Text(value)
                    .font(.system(.title, design: .rounded, weight: .bold))
                Text(title)
                    .font(.caption)
                    .foregroundColor(.secondary)
            }
            .frame(maxWidth: .infinity)
            .padding(.vertical, 6)
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
        HStack(spacing: 10) {
            Image(systemName: status ? "checkmark.circle.fill" : "xmark.circle.fill")
                .foregroundColor(status ? .green : .red)
                .font(.subheadline)
            Text(label)
                .font(.subheadline)
                .fontWeight(.medium)
            Spacer()
            Text(detail)
                .font(.subheadline)
                .foregroundColor(.secondary)
        }
    }
}
