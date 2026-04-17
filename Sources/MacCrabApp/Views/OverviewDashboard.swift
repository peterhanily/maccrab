// OverviewDashboard.swift
// MacCrabApp
//
// The overview homepage — the first thing users see.
// Shows call-to-action banners, stats, severity distribution,
// recent alerts, and system health at a glance.

import SwiftUI

struct OverviewDashboard: View {
    @ObservedObject var appState: AppState
    @ObservedObject var sysextManager: SystemExtensionManager
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
            // While the system extension isn't activated, the sysext
            // panel is the ONLY useful thing on this page — it's how
            // the user starts protection. Show it unconditionally at
            // the top so we never hide the activation control behind
            // a "connecting to daemon" spinner that can never resolve
            // (the daemon is the sysext; activating it *is* the
            // connection). Once the sysext is active, fall through to
            // the normal "connecting" spinner (brief, while the
            // dashboard reads its first rows from the DB) and then
            // the full overview.
            if sysextManager.state != .activated {
                VStack(alignment: .leading, spacing: 20) {
                    SystemExtensionPanel(manager: sysextManager)
                    if !appState.isConnected {
                        Text("Enable protection above to start the detection engine.")
                            .font(.subheadline)
                            .foregroundColor(.secondary)
                            .padding(.horizontal, 4)
                    }
                }
                .padding()
            } else if !appState.isConnected && appState.rulesLoaded == 0 {
                VStack(spacing: 12) {
                    ProgressView()
                        .scaleEffect(1.5)
                    Text(String(localized: "overview.connecting", defaultValue: "Connecting to the detection engine\u{2026}"))
                        .font(.headline)
                        .foregroundColor(.secondary)
                    Text("The extension is active — populating the dashboard.")
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
                                .accessibilityHidden(true)
                            VStack(alignment: .leading, spacing: 4) {
                                if criticalCount > 0 {
                                    Text("\(criticalCount) critical alert\(criticalCount == 1 ? "" : "s") need\(criticalCount == 1 ? "s" : "") investigation")
                                        .font(.system(.body, weight: .semibold))
                                        .foregroundColor(.white)
                                    Text(String(localized: "overview.reviewAlerts", defaultValue: "Click to review in Alerts"))
                                        .font(.subheadline)
                                        .foregroundColor(.white.opacity(0.8))
                                } else if highCount > 0 {
                                    Text("\(highCount) high-severity alert\(highCount == 1 ? "" : "s") to review")
                                        .font(.system(.body, weight: .semibold))
                                        .foregroundColor(.white)
                                    Text(String(localized: "overview.reviewAlerts", defaultValue: "Click to review in Alerts"))
                                        .font(.subheadline)
                                        .foregroundColor(.white.opacity(0.8))
                                } else {
                                    Text(String(localized: "overview.allClear", defaultValue: "All clear \u{2014} no critical alerts"))
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
                                .flipsForRightToLeftLayoutDirection(true)
                                .accessibilityHidden(true)
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
                        StatCard(title: "Security", value: appState.securityGrade.isEmpty ? "\u{2014}" : appState.securityGrade, icon: "shield.checkered", color: appState.securityGrade.isEmpty ? .secondary : appState.securityScore >= 80 ? .green : appState.securityScore >= 60 ? .orange : .red)
                    }
                    .padding(.horizontal)

                    // === Prevention Status ===
                    Button { selectedSection = .prevention } label: {
                        HStack(spacing: 10) {
                            Image(systemName: preventionActive ? "shield.checkered" : "shield")
                                .font(.title3)
                                .foregroundColor(preventionActive ? .green : .secondary)
                                .accessibilityHidden(true)
                            VStack(alignment: .leading, spacing: 2) {
                                Text(preventionActive ? "Prevention Active" : "Prevention Off")
                                    .font(.subheadline)
                                    .fontWeight(.medium)
                                    .foregroundColor(.primary)
                                Text(preventionActive ? "DNS sinkhole, network blocker, and more enabled" : "Enable prevention in the Prevention tab")
                                    .font(.caption)
                                    .foregroundColor(.secondary)
                            }
                            Spacer()
                            Image(systemName: "chevron.right")
                                .font(.caption)
                                .foregroundColor(.secondary)
                                .flipsForRightToLeftLayoutDirection(true)
                                .accessibilityHidden(true)
                        }
                        .padding(10)
                        .background(Color.secondary.opacity(0.06))
                        .cornerRadius(8)
                    }
                    .buttonStyle(.plain)
                    .padding(.horizontal)

                    // === Severity Breakdown ===
                    GroupBox("Alert Severity") {
                        HStack(spacing: 20) {
                            SeverityCount(label: "Critical", count: criticalCount, color: criticalColor)
                            SeverityCount(label: "High", count: highCount, color: highColor)
                            SeverityCount(label: "Medium", count: mediumCount, color: .yellow)
                            SeverityCount(label: "Low", count: lowCount, color: .blue)
                        }
                        .padding(8)
                    }
                    .padding(.horizontal)

                    HStack(alignment: .top, spacing: 16) {
                        // === Recent Alerts ===
                        GroupBox("Recent Alerts") {
                            if appState.recentAlerts.isEmpty {
                                Text(String(localized: "overview.noRecentAlerts", defaultValue: "No recent alerts"))
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
                                                    .flipsForRightToLeftLayoutDirection(true)
                                                    .accessibilityHidden(true)
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
                    .accessibilityHidden(true)
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

struct SeverityCount: View {
    let label: String
    let count: Int
    let color: Color

    var body: some View {
        HStack(spacing: 6) {
            Circle()
                .fill(color)
                .frame(width: 10, height: 10)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 1) {
                Text("\(count)")
                    .font(.system(.title3, design: .rounded, weight: .bold))
                Text(label)
                    .font(.caption)
                    .foregroundColor(.secondary)
            }
        }
        .frame(maxWidth: .infinity)
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(count) \(label)")
    }
}

// Kept for backward compatibility but no longer used in Overview
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
                .accessibilityLabel(status ? "OK" : "Failed")
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
