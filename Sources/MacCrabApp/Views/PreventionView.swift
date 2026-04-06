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

                Divider()

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
