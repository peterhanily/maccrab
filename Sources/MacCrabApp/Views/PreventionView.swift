import SwiftUI

struct PreventionView: View {
    @ObservedObject var appState: AppState

    // Prevention toggle states (persisted via @AppStorage)
    @AppStorage("prevention.dnsSinkhole") private var dnsSinkholeEnabled = false
    @AppStorage("prevention.networkBlocker") private var networkBlockerEnabled = false
    @AppStorage("prevention.persistenceGuard") private var persistenceGuardEnabled = false
    @AppStorage("prevention.sandboxAnalysis") private var sandboxAnalysisEnabled = false
    @AppStorage("prevention.aiContainment") private var aiContainmentEnabled = false
    @AppStorage("prevention.supplyChainGate") private var supplyChainGateEnabled = false
    @AppStorage("prevention.tccRevocation") private var tccRevocationEnabled = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                // Header
                HStack {
                    Text("Prevention")
                        .font(.title2).fontWeight(.bold)
                    Spacer()
                    // Master toggle
                    Toggle("Enable All", isOn: Binding(
                        get: { allEnabled },
                        set: { setAll($0) }
                    ))
                    .toggleStyle(.switch)
                }
                .padding(.horizontal)
                .padding(.top)

                Text("Active prevention blocks threats before they cause damage. Each mechanism can be individually enabled or disabled.")
                    .font(.caption)
                    .foregroundColor(.secondary)
                    .padding(.horizontal)

                // === Metrics Dashboard ===
                HStack(spacing: 16) {
                    MetricBox(label: "Threats Blocked", value: "\(preventionAlertCount)", icon: "hand.raised.fill", color: .red)
                    MetricBox(label: "Domains Sinkholed", value: "\(sinkholeCount)", icon: "network.slash", color: .blue)
                    MetricBox(label: "IPs Blocked", value: "\(blockedIPCount)", icon: "shield.lefthalf.filled", color: .orange)
                    MetricBox(label: "Packages Gated", value: "\(packagesGated)", icon: "shippingbox", color: .yellow)
                }
                .padding(.horizontal)

                // Recent prevention activity
                if !recentBlocks.isEmpty {
                    GroupBox("Recent Prevention Activity") {
                        VStack(alignment: .leading, spacing: 6) {
                            ForEach(recentBlocks.prefix(5), id: \.id) { alert in
                                HStack(spacing: 8) {
                                    Image(systemName: "xmark.shield.fill")
                                        .foregroundColor(.red)
                                        .font(.caption)
                                    VStack(alignment: .leading, spacing: 1) {
                                        Text(alert.ruleTitle)
                                            .font(.caption)
                                            .fontWeight(.medium)
                                            .lineLimit(1)
                                        Text(alert.description)
                                            .font(.caption2)
                                            .foregroundColor(.secondary)
                                            .lineLimit(1)
                                    }
                                    Spacer()
                                    Text(alert.timeAgoString)
                                        .font(.caption2)
                                        .foregroundColor(.secondary)
                                }
                            }
                        }
                        .padding(4)
                    }
                    .padding(.horizontal)
                }

                Divider()

                Text("Prevention Mechanisms")
                    .font(.headline)
                    .padding(.horizontal)

                // Prevention mechanisms
                VStack(spacing: 12) {
                    PreventionCard(
                        title: "DNS Sinkhole",
                        description: "Redirects known-malicious domains to localhost, preventing C2 callbacks and data exfiltration",
                        icon: "network.slash",
                        color: .blue,
                        isEnabled: $dnsSinkholeEnabled,
                        status: "Threat intel domains → 127.0.0.1"
                    )

                    PreventionCard(
                        title: "Network Blocker",
                        description: "Blocks outbound connections to threat intelligence IPs using PF firewall tables",
                        icon: "shield.lefthalf.filled",
                        color: .red,
                        isEnabled: $networkBlockerEnabled,
                        status: "PF table-based bidirectional blocking"
                    )

                    PreventionCard(
                        title: "Persistence Guard",
                        description: "Locks LaunchAgent/LaunchDaemon directories with system immutable flag to prevent unauthorized persistence",
                        icon: "lock.shield",
                        color: .orange,
                        isEnabled: $persistenceGuardEnabled,
                        status: "chflags SF_IMMUTABLE on persistence dirs"
                    )

                    PreventionCard(
                        title: "Sandbox Analysis",
                        description: "Runs unnotarized binaries from Downloads/tmp in a restricted sandbox before allowing full execution",
                        icon: "cube.transparent",
                        color: .purple,
                        isEnabled: $sandboxAnalysisEnabled,
                        status: "sandbox-exec with network + file-write deny"
                    )

                    PreventionCard(
                        title: "AI Tool Containment",
                        description: "Locks credential files (SSH keys, AWS, .env) to prevent AI coding tools from reading sensitive data",
                        icon: "brain",
                        color: .green,
                        isEnabled: $aiContainmentEnabled,
                        status: "chmod 0o400 on credential files"
                    )

                    PreventionCard(
                        title: "Supply Chain Gate",
                        description: "Kills package installer processes when freshness check detects packages published less than 24 hours ago",
                        icon: "shippingbox",
                        color: .yellow,
                        isEnabled: $supplyChainGateEnabled,
                        status: "SIGTERM → SIGKILL on critical-risk installs"
                    )

                    PreventionCard(
                        title: "TCC Auto-Revocation",
                        description: "Automatically revokes Camera, Microphone, ScreenCapture permissions from unsigned or ad-hoc signed apps",
                        icon: "hand.raised",
                        color: .pink,
                        isEnabled: $tccRevocationEnabled,
                        status: "tccutil reset for unsigned apps"
                    )
                }
                .padding(.horizontal)

                Spacer()
            }
        }
    }

    // === Metrics computed from alert database ===

    private var preventionAlertCount: Int {
        appState.dashboardAlerts.filter { $0.ruleTitle.contains("BLOCKED") || $0.ruleTitle.contains("Prevention") || $0.ruleTitle.lowercased().contains("sinkhole") }.count
    }

    private var sinkholeCount: Int {
        appState.dashboardAlerts.filter { $0.ruleTitle.lowercased().contains("sinkhole") || $0.ruleTitle.lowercased().contains("dns") && $0.ruleTitle.contains("blocked") }.count
    }

    private var blockedIPCount: Int {
        appState.dashboardAlerts.filter { $0.ruleTitle.lowercased().contains("network") && $0.ruleTitle.contains("BLOCKED") }.count
    }

    private var packagesGated: Int {
        appState.dashboardAlerts.filter { $0.ruleTitle.contains("supply-chain-blocked") || $0.ruleTitle.contains("Package Install Killed") }.count
    }

    private var recentBlocks: [AlertViewModel] {
        appState.dashboardAlerts.filter {
            $0.ruleTitle.contains("BLOCKED") || $0.ruleTitle.contains("Prevention") ||
            $0.ruleTitle.contains("Sandbox") || $0.ruleTitle.contains("sinkhole") ||
            $0.ruleTitle.contains("Revoked") || $0.ruleTitle.contains("supply-chain")
        }.prefix(5).map { $0 }
    }

    private var allEnabled: Bool {
        dnsSinkholeEnabled && networkBlockerEnabled && persistenceGuardEnabled &&
        sandboxAnalysisEnabled && aiContainmentEnabled && supplyChainGateEnabled && tccRevocationEnabled
    }

    private func setAll(_ enabled: Bool) {
        dnsSinkholeEnabled = enabled
        networkBlockerEnabled = enabled
        persistenceGuardEnabled = enabled
        sandboxAnalysisEnabled = enabled
        aiContainmentEnabled = enabled
        supplyChainGateEnabled = enabled
        tccRevocationEnabled = enabled
    }
}

// MARK: - Prevention Card

struct PreventionCard: View {
    let title: String
    let description: String
    let icon: String
    let color: Color
    @Binding var isEnabled: Bool
    let status: String

    var body: some View {
        GroupBox {
            HStack(alignment: .top, spacing: 12) {
                // Icon
                Image(systemName: icon)
                    .font(.title2)
                    .foregroundColor(isEnabled ? color : .secondary)
                    .frame(width: 32)

                // Content
                VStack(alignment: .leading, spacing: 4) {
                    HStack {
                        Text(title)
                            .font(.headline)
                        Spacer()
                        Toggle("", isOn: $isEnabled)
                            .toggleStyle(.switch)
                            .labelsHidden()
                    }

                    Text(description)
                        .font(.caption)
                        .foregroundColor(.secondary)

                    if isEnabled {
                        HStack(spacing: 4) {
                            Circle()
                                .fill(.green)
                                .frame(width: 6, height: 6)
                            Text(status)
                                .font(.caption2)
                                .foregroundColor(.green)
                        }
                        .padding(.top, 2)
                    }
                }
            }
            .padding(4)
        }
        .opacity(isEnabled ? 1.0 : 0.7)
    }
}

// MARK: - Metric Box

struct MetricBox: View {
    let label: String
    let value: String
    let icon: String
    let color: Color

    var body: some View {
        GroupBox {
            VStack(spacing: 6) {
                Image(systemName: icon)
                    .font(.title3)
                    .foregroundColor(color)
                Text(value)
                    .font(.system(.title2, design: .rounded, weight: .bold))
                Text(label)
                    .font(.caption2)
                    .foregroundColor(.secondary)
                    .multilineTextAlignment(.center)
            }
            .frame(maxWidth: .infinity)
            .padding(.vertical, 4)
        }
    }
}
