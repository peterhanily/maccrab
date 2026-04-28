import SwiftUI

struct PreventionView: View {
    @ObservedObject var appState: AppState
    @Environment(\.accessibilityReduceMotion) var reduceMotion

    /// v1.7.2: search across recent prevention activity by ruleTitle,
    /// description, processName, processPath.
    @State private var searchText: String = ""
    /// v1.7.2: when set, the prevention card detail sheet opens for
    /// this mechanism (showing only its recent activity).
    @State private var inspectMechanism: PreventionMechanism?

    enum PreventionMechanism: String, Identifiable {
        case dnsSinkhole = "DNS Sinkhole"
        case networkBlocker = "Network Blocker"
        case persistenceGuard = "Persistence Guard"
        case sandboxAnalysis = "Sandbox Analysis"
        case aiContainment = "AI Tool Containment"
        case supplyChainGate = "Supply Chain Gate"
        case tccRevocation = "TCC Revocation"
        /// v1.7.2 review fix: explicit "Other" bucket for alerts whose
        /// rule title doesn't match any known mechanism. Previously
        /// fell through to `.aiContainment` which mis-labeled the drill.
        case other = "Other Prevention"
        var id: String { rawValue }
        var titleFilterTokens: [String] {
            switch self {
            case .dnsSinkhole:      return ["sinkhole", "dns"]
            case .networkBlocker:   return ["network", "BLOCKED"]
            case .persistenceGuard: return ["LaunchAgent", "Persistence", "Restored"]
            case .sandboxAnalysis:  return ["Sandbox"]
            case .aiContainment:    return ["AI Guard", "credential", "fence"]
            case .supplyChainGate:  return ["supply-chain", "Package Install"]
            case .tccRevocation:    return ["Revoked", "TCC"]
            case .other:            return [] // matches nothing; sheet shows the explanatory copy
            }
        }
    }

    // Prevention toggle states (persisted via @AppStorage)
    @AppStorage("prevention.dnsSinkhole") private var dnsSinkholeEnabled = false
    @AppStorage("prevention.networkBlocker") private var networkBlockerEnabled = false
    @AppStorage("prevention.persistenceGuard") private var persistenceGuardEnabled = false
    @AppStorage("prevention.sandboxAnalysis") private var sandboxAnalysisEnabled = false
    @AppStorage("prevention.aiContainment") private var aiContainmentEnabled = false
    @AppStorage("prevention.supplyChainGate") private var supplyChainGateEnabled = false
    @AppStorage("prevention.tccRevocation") private var tccRevocationEnabled = false

    private var toggleHash: Int {
        var h = 0
        if dnsSinkholeEnabled { h |= 1 }
        if networkBlockerEnabled { h |= 2 }
        if persistenceGuardEnabled { h |= 4 }
        if sandboxAnalysisEnabled { h |= 8 }
        if aiContainmentEnabled { h |= 16 }
        if supplyChainGateEnabled { h |= 32 }
        if tccRevocationEnabled { h |= 64 }
        return h
    }

    private func syncPreventionConfig() {
        let configDir = NSHomeDirectory() + "/Library/Application Support/MacCrab"
        try? FileManager.default.createDirectory(atPath: configDir, withIntermediateDirectories: true)
        let configPath = configDir + "/prevention_config.json"
        let anyEnabled = dnsSinkholeEnabled || networkBlockerEnabled || persistenceGuardEnabled ||
            sandboxAnalysisEnabled || aiContainmentEnabled || supplyChainGateEnabled || tccRevocationEnabled
        let config: [String: Any] = [
            "enabled": anyEnabled,
            "dnsSinkhole": dnsSinkholeEnabled,
            "networkBlocker": networkBlockerEnabled,
            "persistenceGuard": persistenceGuardEnabled,
            "sandboxAnalysis": sandboxAnalysisEnabled,
            "aiContainment": aiContainmentEnabled,
            "supplyChainGate": supplyChainGateEnabled,
            "tccRevocation": tccRevocationEnabled,
            "updatedAt": ISO8601DateFormatter().string(from: Date())
        ]
        if let data = try? JSONSerialization.data(withJSONObject: config) {
            try? data.write(to: URL(fileURLWithPath: configPath))
        }
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                // Header
                HStack {
                    Text(String(localized: "prevention.title", defaultValue: "Prevention"))
                        .font(.title2).fontWeight(.bold)
                    Spacer()
                    HStack(spacing: 4) {
                        Image(systemName: "magnifyingglass")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                        TextField("Search prevention activity", text: $searchText)
                            .textFieldStyle(.roundedBorder)
                            .controlSize(.small)
                            .frame(minWidth: 160, idealWidth: 200, maxWidth: 280)
                    }
                    // Master toggle
                    Toggle(String(localized: "prevention.enableAll", defaultValue: "Enable All"), isOn: Binding(
                        get: { allEnabled },
                        set: { setAll($0) }
                    ))
                    .toggleStyle(.switch)
                    .accessibilityLabel(String(localized: "prevention.enableAll", defaultValue: "Enable All"))
                    .accessibilityHint(String(localized: "prevention.enableAllHint", defaultValue: "Toggles all prevention mechanisms on or off"))
                    .keyboardShortcut("p", modifiers: .command)
                }
                .padding(.horizontal)
                .padding(.top)

                Text(String(localized: "prevention.description", defaultValue: "Active prevention blocks threats before they cause damage. Each mechanism can be individually enabled or disabled."))
                    .font(.caption)
                    .foregroundColor(.secondary)
                    .padding(.horizontal)

                // === Metrics Dashboard ===
                HStack(spacing: 16) {
                    MetricBox(label: String(localized: "prevention.threatsBlocked", defaultValue: "Threats Blocked"), value: "\(preventionAlertCount)", icon: "hand.raised.fill", color: .red)
                    MetricBox(label: String(localized: "prevention.domainsSinkholed", defaultValue: "Domains Sinkholed"), value: "\(sinkholeCount)", icon: "network.slash", color: .blue)
                    MetricBox(label: String(localized: "prevention.ipsBlocked", defaultValue: "IPs Blocked"), value: "\(blockedIPCount)", icon: "shield.lefthalf.filled", color: .orange)
                    MetricBox(label: String(localized: "prevention.packagesGated", defaultValue: "Packages Gated"), value: "\(packagesGated)", icon: "shippingbox", color: .yellow)
                }
                .padding(.horizontal)

                // Recent prevention activity
                if !recentBlocks.isEmpty {
                    GroupBox(String(localized: "prevention.recentActivity", defaultValue: "Recent Prevention Activity")) {
                        VStack(alignment: .leading, spacing: 6) {
                            ForEach(recentBlocks.prefix(5), id: \.id) { alert in
                                Button {
                                    // v1.7.2: tap a recent block → open
                                    // the per-mechanism drill sheet for
                                    // the inferred mechanism.
                                    inspectMechanism = inferMechanism(from: alert)
                                } label: {
                                    HStack(spacing: 8) {
                                        Image(systemName: "xmark.shield.fill")
                                            .foregroundColor(.red)
                                            .font(.caption)
                                            .accessibilityHidden(true)
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
                                        Image(systemName: "chevron.right")
                                            .font(.caption2)
                                            .foregroundStyle(.tertiary)
                                    }
                                    .contentShape(Rectangle())
                                }
                                .buttonStyle(.plain)
                            }
                        }
                        .padding(4)
                    }
                    .padding(.horizontal)
                }

                Divider()

                Text(String(localized: "prevention.mechanisms", defaultValue: "Prevention Mechanisms"))
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
                        status: "Threat intel domains \u{2192} 127.0.0.1",
                        accessibilityHintText: "Enables DNS sinkhole protection"
                    )

                    PreventionCard(
                        title: "Network Blocker",
                        description: "Blocks outbound connections to threat intelligence IPs using PF firewall tables",
                        icon: "shield.lefthalf.filled",
                        color: .red,
                        isEnabled: $networkBlockerEnabled,
                        status: "PF table-based bidirectional blocking",
                        accessibilityHintText: "Enables firewall-based IP blocking"
                    )

                    PreventionCard(
                        title: "Persistence Guard",
                        description: "Locks LaunchAgent/LaunchDaemon directories with system immutable flag to prevent unauthorized persistence",
                        icon: "lock.shield",
                        color: .orange,
                        isEnabled: $persistenceGuardEnabled,
                        status: "chflags SF_IMMUTABLE on persistence dirs",
                        accessibilityHintText: "Enables persistence directory locking"
                    )

                    PreventionCard(
                        title: "Sandbox Analysis",
                        description: "Runs unnotarized binaries from Downloads/tmp in a restricted sandbox before allowing full execution",
                        icon: "cube.transparent",
                        color: .purple,
                        isEnabled: $sandboxAnalysisEnabled,
                        status: "sandbox-exec with network + file-write deny",
                        accessibilityHintText: "Enables sandbox analysis for untrusted binaries"
                    )

                    PreventionCard(
                        title: "AI Tool Containment",
                        description: "Locks credential files (SSH keys, AWS, .env) to prevent AI coding tools from reading sensitive data",
                        icon: "brain",
                        color: .green,
                        isEnabled: $aiContainmentEnabled,
                        status: "chmod 0o400 on credential files",
                        accessibilityHintText: "Enables credential file locking for AI tools"
                    )

                    PreventionCard(
                        title: "Supply Chain Gate",
                        description: "Kills package installer processes when freshness check detects packages published less than 24 hours ago",
                        icon: "shippingbox",
                        color: .yellow,
                        isEnabled: $supplyChainGateEnabled,
                        status: "SIGTERM \u{2192} SIGKILL on critical-risk installs",
                        accessibilityHintText: "Enables automatic blocking of suspicious package installs"
                    )

                    PreventionCard(
                        title: "TCC Auto-Revocation",
                        description: "Automatically revokes Camera, Microphone, ScreenCapture permissions from unsigned or ad-hoc signed apps",
                        icon: "hand.raised",
                        color: .pink,
                        isEnabled: $tccRevocationEnabled,
                        status: "tccutil reset for unsigned apps",
                        accessibilityHintText: "Enables automatic permission revocation for unsigned apps"
                    )
                }
                .padding(.horizontal)

                Spacer()
            }
        }
        .onChange(of: toggleHash) { _ in syncPreventionConfig() }
        .onAppear { syncPreventionConfig() }
        .sheet(item: $inspectMechanism) { mechanism in
            mechanismDetailSheet(mechanism)
        }
    }

    @ViewBuilder
    private func mechanismDetailSheet(_ mechanism: PreventionMechanism) -> some View {
        let alerts = alertsForMechanism(mechanism)
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Text(mechanism.rawValue).font(.title2.weight(.bold))
                Spacer()
                Button("Close") { inspectMechanism = nil }
                    .keyboardShortcut(.cancelAction)
            }
            Text("\(alerts.count) recent alert(s) attributed to this mechanism")
                .font(.caption)
                .foregroundStyle(.secondary)
            Divider()
            if alerts.isEmpty {
                Spacer()
                Text("No activity for this mechanism yet.")
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity)
                Spacer()
            } else {
                ScrollView {
                    VStack(alignment: .leading, spacing: 6) {
                        ForEach(alerts.prefix(50), id: \.id) { alert in
                            HStack(alignment: .top, spacing: 8) {
                                Image(systemName: "xmark.shield.fill")
                                    .foregroundColor(.red)
                                    .font(.caption)
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(alert.ruleTitle).font(.subheadline.weight(.medium))
                                    Text(alert.description).font(.caption).foregroundStyle(.secondary)
                                    Text(alert.timeAgoString).font(.caption2).foregroundStyle(.tertiary)
                                }
                                Spacer()
                            }
                            .padding(8)
                            .background(Color.secondary.opacity(0.05))
                            .clipShape(RoundedRectangle(cornerRadius: 4))
                        }
                    }
                }
            }
        }
        .padding()
        .frame(minWidth: 540, minHeight: 420)
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
        let base = appState.dashboardAlerts.filter {
            $0.ruleTitle.contains("BLOCKED") || $0.ruleTitle.contains("Prevention") ||
            $0.ruleTitle.contains("Sandbox") || $0.ruleTitle.contains("sinkhole") ||
            $0.ruleTitle.contains("Revoked") || $0.ruleTitle.contains("supply-chain")
        }
        let filtered: [AlertViewModel]
        if searchText.isEmpty {
            filtered = base
        } else {
            let q = searchText.lowercased()
            filtered = base.filter {
                $0.ruleTitle.lowercased().contains(q)
                    || $0.description.lowercased().contains(q)
                    || ($0.processName ?? "").lowercased().contains(q)
                    || ($0.processPath ?? "").lowercased().contains(q)
            }
        }
        return Array(filtered.prefix(5))
    }

    /// v1.7.2: alerts produced by a specific prevention mechanism, for
    /// the per-mechanism drill sheet.
    private func alertsForMechanism(_ m: PreventionMechanism) -> [AlertViewModel] {
        let tokens = m.titleFilterTokens.map { $0.lowercased() }
        return appState.dashboardAlerts.filter { alert in
            let title = alert.ruleTitle.lowercased()
            return tokens.contains(where: { title.contains($0) })
        }
    }

    /// v1.7.2: best-guess mapping from an alert to the prevention
    /// mechanism that fired it, used to drill from a Recent Activity
    /// row into the per-mechanism sheet.
    private func inferMechanism(from alert: AlertViewModel) -> PreventionMechanism {
        let title = alert.ruleTitle.lowercased()
        if title.contains("sinkhole") || title.contains("dns") {
            return .dnsSinkhole
        } else if title.contains("supply-chain") || title.contains("package") {
            return .supplyChainGate
        } else if title.contains("network") && title.contains("blocked") {
            return .networkBlocker
        } else if title.contains("sandbox") {
            return .sandboxAnalysis
        } else if title.contains("revoked") || title.contains("tcc") {
            return .tccRevocation
        } else if title.contains("launchagent") || title.contains("persistence") {
            return .persistenceGuard
        } else if title.contains("ai guard") || title.contains("credential") || title.contains("fence") {
            return .aiContainment
        }
        return .other
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
        syncPreventionConfig()
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
    var accessibilityHintText: String = ""

    var body: some View {
        GroupBox {
            HStack(alignment: .top, spacing: 12) {
                // Icon
                Image(systemName: icon)
                    .font(.title2)
                    .foregroundColor(isEnabled ? color : .secondary)
                    .frame(width: 32)
                    .accessibilityHidden(true)

                // Content
                VStack(alignment: .leading, spacing: 4) {
                    HStack {
                        Text(title)
                            .font(.headline)
                        Spacer()
                        Toggle("", isOn: $isEnabled)
                            .toggleStyle(.switch)
                            .labelsHidden()
                            .accessibilityLabel("\(title) toggle")
                            .accessibilityHint(accessibilityHintText)
                    }

                    Text(description)
                        .font(.caption)
                        .foregroundColor(.secondary)

                    if isEnabled {
                        HStack(spacing: 4) {
                            Circle()
                                .fill(.green)
                                .frame(width: 6, height: 6)
                                .accessibilityHidden(true)
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
        .accessibilityElement(children: .combine)
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
                    .accessibilityHidden(true)
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
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(label): \(value)")
    }
}
