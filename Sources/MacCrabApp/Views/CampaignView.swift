// CampaignView.swift
// MacCrabApp
//
// Shows detected campaigns — kill chains, alert storms, AI compromise,
// and coordinated attacks identified by the campaign detector.

import SwiftUI

struct CampaignView: View {
    @ObservedObject var appState: AppState

    /// Campaign alerts identified by the canonical ruleId prefix.
    var campaigns: [AlertViewModel] {
        appState.dashboardAlerts.filter {
            $0.ruleId.hasPrefix("maccrab.campaign.") && !$0.suppressed && !appState.isPatternSuppressed($0)
        }
    }

    var dismissedCampaigns: [AlertViewModel] {
        appState.dashboardAlerts.filter {
            $0.ruleId.hasPrefix("maccrab.campaign.") && ($0.suppressed || appState.isPatternSuppressed($0))
        }
    }

    @State private var expandedCampaignId: String? = nil
    @State private var showDismissed = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                // Header
                HStack {
                    Text(String(localized: "campaigns.title", defaultValue: "Campaigns & Incidents"))
                        .font(.title2).fontWeight(.bold)
                    Spacer()
                    if !dismissedCampaigns.isEmpty {
                        Button {
                            showDismissed.toggle()
                        } label: {
                            Label(
                                showDismissed
                                    ? String(localized: "campaigns.hideDismissed", defaultValue: "Hide Dismissed")
                                    : "\(dismissedCampaigns.count) \(String(localized: "campaigns.dismissed", defaultValue: "dismissed"))",
                                systemImage: showDismissed ? "eye.slash" : "eye"
                            )
                            .font(.caption)
                        }
                        .controlSize(.small)
                    }
                    Text("\(campaigns.count) \(String(localized: "campaigns.active", defaultValue: "active"))")
                        .font(.subheadline)
                        .foregroundColor(.secondary)
                }
                .padding(.horizontal)
                .padding(.top)

                Text(String(localized: "campaigns.description", defaultValue: "Campaigns are higher-order detections that chain multiple alerts into attack patterns — kill chains, alert storms, AI compromise, and coordinated attacks."))
                    .font(.subheadline)
                    .foregroundColor(.secondary)
                    .padding(.horizontal)

                if campaigns.isEmpty && !showDismissed {
                    VStack(spacing: 12) {
                        Spacer()
                        Image(systemName: "shield.checkered")
                            .font(.system(size: 48))
                            .foregroundColor(.secondary.opacity(0.5))
                            .accessibilityHidden(true)
                        Text(String(localized: "campaigns.none", defaultValue: "No active campaigns"))
                            .font(.headline)
                            .foregroundColor(.secondary)
                        Text(String(localized: "campaigns.noneDetail", defaultValue: "This is good — no multi-stage attacks have been identified"))
                            .font(.subheadline)
                            .foregroundColor(.secondary)
                        Spacer()
                    }
                    .frame(maxWidth: .infinity)
                    .padding(40)
                } else {
                    VStack(spacing: 12) {
                        ForEach(campaigns, id: \.id) { campaign in
                            CampaignCard(
                                campaign: campaign,
                                isExpanded: expandedCampaignId == campaign.id,
                                relatedAlerts: relatedAlerts(for: campaign),
                                onToggle: {
                                    withAnimation(.easeInOut(duration: 0.2)) {
                                        expandedCampaignId = expandedCampaignId == campaign.id ? nil : campaign.id
                                    }
                                },
                                onDismiss: {
                                    Task { await appState.suppressAlert(campaign.id) }
                                }
                            )
                        }

                        if showDismissed {
                            if !dismissedCampaigns.isEmpty {
                                Divider().padding(.vertical, 4)
                                Text(String(localized: "campaigns.dismissedSection", defaultValue: "Dismissed Campaigns"))
                                    .font(.caption).foregroundColor(.secondary)
                                ForEach(dismissedCampaigns, id: \.id) { campaign in
                                    CampaignCard(
                                        campaign: campaign,
                                        isExpanded: expandedCampaignId == campaign.id,
                                        relatedAlerts: relatedAlerts(for: campaign),
                                        onToggle: {
                                            withAnimation(.easeInOut(duration: 0.2)) {
                                                expandedCampaignId = expandedCampaignId == campaign.id ? nil : campaign.id
                                            }
                                        },
                                        onDismiss: nil,
                                        onRestore: {
                                            Task { await appState.unsuppressAlert(campaign.id) }
                                        }
                                    )
                                    .opacity(0.6)
                                }
                            }
                        }
                    }
                    .padding(.horizontal)
                }

                Spacer()
            }
        }
        .navigationTitle("Campaigns")
    }

    /// Find alerts that occurred around the same time as a campaign and share tactics.
    private func relatedAlerts(for campaign: AlertViewModel) -> [AlertViewModel] {
        let window: TimeInterval = 600 // Campaign window
        return appState.dashboardAlerts.filter { alert in
            !alert.ruleId.hasPrefix("maccrab.campaign.")
            && !alert.ruleId.hasPrefix("maccrab.llm.")
            && abs(alert.timestamp.timeIntervalSince(campaign.timestamp)) < window
        }
        .sorted { $0.timestamp < $1.timestamp }
    }
}

struct CampaignCard: View {
    let campaign: AlertViewModel
    let isExpanded: Bool
    let relatedAlerts: [AlertViewModel]
    let onToggle: () -> Void
    let onDismiss: (() -> Void)?
    var onRestore: (() -> Void)? = nil

    /// Extract the campaign type from the ruleId.
    private var campaignType: String {
        campaign.ruleId
            .replacingOccurrences(of: "maccrab.campaign.", with: "")
            .replacingOccurrences(of: "_", with: " ")
            .capitalized
    }

    /// Split tactics string into individual items.
    private var tactics: [String] {
        campaign.mitreTechniques
            .split(separator: ",")
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
    }

    /// Generate actionable guidance based on campaign type and severity.
    private var guidance: [(icon: String, text: String)] {
        var items: [(String, String)] = []

        let type = campaign.ruleId.replacingOccurrences(of: "maccrab.campaign.", with: "")

        switch type {
        case "kill_chain":
            items.append(("exclamationmark.shield", "Isolate the affected machine from the network if possible"))
            items.append(("magnifyingglass", "Review the contributing alerts below to identify the initial access vector"))
            items.append(("trash", "Check for persistence mechanisms (LaunchAgents, cron jobs, login items)"))
            items.append(("person.fill.questionmark", "Determine if any credentials were accessed — rotate if so"))
        case "alert_storm":
            items.append(("waveform.path.ecg", "Likely a scan or brute-force — check if the source is internal or external"))
            items.append(("hand.raised", "Consider blocking the source IP or process if the activity is unauthorized"))
            items.append(("eye", "Monitor for follow-up activity — storms often precede targeted exploitation"))
        case "ai_compromise":
            items.append(("brain", "Review what the AI tool accessed — check credential fence logs"))
            items.append(("lock.shield", "Revoke any API keys or tokens the AI tool may have read"))
            items.append(("folder.badge.minus", "Audit project boundaries — ensure the tool stayed within its workspace"))
            items.append(("arrow.counterclockwise", "Consider restarting the AI tool session to clear any injected context"))
        case "coordinated_attack":
            items.append(("person.crop.circle.badge.exclamationmark", "A single process is exhibiting multi-tactic behavior — likely compromised"))
            items.append(("xmark.circle", "Terminate the process if it's not a known legitimate tool"))
            items.append(("magnifyingglass", "Trace the process lineage to find the initial compromise"))
            items.append(("clock.arrow.circlepath", "Check for data exfiltration in the contributing alerts"))
        case "lateral_movement":
            items.append(("person.2", "Activity detected from multiple user accounts — verify each is authorized"))
            items.append(("key", "Rotate credentials for any affected accounts"))
            items.append(("network", "Check for SSH connections or remote access from unusual sources"))
        default:
            items.append(("magnifyingglass", "Review the contributing alerts for context"))
            items.append(("shield.checkered", "Consider enabling prevention features if not already active"))
        }

        if campaign.severity == .critical {
            items.insert(("exclamationmark.triangle.fill", "CRITICAL: This requires immediate investigation"), at: 0)
        }

        return items
    }

    var body: some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 8) {
                // Header row — clickable to expand
                Button(action: onToggle) {
                    HStack {
                        Image(systemName: campaign.severity.sfSymbol)
                            .foregroundColor(campaign.severityColor)
                            .font(.title3)
                        VStack(alignment: .leading, spacing: 2) {
                            Text(campaign.ruleTitle)
                                .font(.headline)
                                .foregroundColor(.primary)
                            Text(campaignType)
                                .font(.caption)
                                .foregroundColor(.secondary)
                        }
                        Spacer()
                        Text(campaign.timeAgoString)
                            .font(.caption)
                            .foregroundColor(.secondary)
                        Image(systemName: isExpanded ? "chevron.up" : "chevron.down")
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }
                }
                .buttonStyle(.plain)

                // Summary line
                Text(campaign.description)
                    .font(.subheadline)
                    .foregroundColor(.secondary)
                    .lineLimit(isExpanded ? nil : 2)

                // Tactics pills
                if !tactics.isEmpty {
                    ScrollView(.horizontal, showsIndicators: false) {
                        HStack(spacing: 6) {
                            ForEach(tactics, id: \.self) { tactic in
                                Text(tactic.replacingOccurrences(of: "attack.", with: ""))
                                    .font(.caption2).fontWeight(.medium)
                                    .padding(.horizontal, 8).padding(.vertical, 3)
                                    .background(Color.orange.opacity(0.15))
                                    .foregroundColor(.orange)
                                    .clipShape(Capsule())
                            }
                        }
                    }
                }

                // Expanded detail section
                if isExpanded {
                    Divider()

                    // What to do
                    VStack(alignment: .leading, spacing: 8) {
                        Text(String(localized: "campaigns.whatToDo", defaultValue: "Recommended Actions"))
                            .font(.subheadline).fontWeight(.semibold)

                        ForEach(Array(guidance.enumerated()), id: \.offset) { _, item in
                            HStack(alignment: .top, spacing: 8) {
                                Image(systemName: item.icon)
                                    .font(.caption)
                                    .foregroundColor(.accentColor)
                                    .frame(width: 16)
                                    .accessibilityHidden(true)
                                Text(item.text)
                                    .font(.caption)
                                    .foregroundColor(.primary)
                            }
                        }
                    }
                    .padding(8)
                    .background(Color.accentColor.opacity(0.05))
                    .cornerRadius(8)

                    // Contributing alerts
                    if !relatedAlerts.isEmpty {
                        VStack(alignment: .leading, spacing: 6) {
                            Text("\(String(localized: "campaigns.contributingAlerts", defaultValue: "Contributing Alerts")) (\(relatedAlerts.count))")
                                .font(.subheadline).fontWeight(.semibold)

                            ForEach(relatedAlerts.prefix(10), id: \.id) { alert in
                                HStack(spacing: 8) {
                                    Image(systemName: alert.severity.sfSymbol)
                                        .font(.caption2)
                                        .foregroundColor(alert.severityColor)
                                    Text(alert.ruleTitle)
                                        .font(.caption)
                                        .lineLimit(1)
                                    Spacer()
                                    if !alert.processName.isEmpty {
                                        Text(alert.processName)
                                            .font(.system(.caption2, design: .monospaced))
                                            .foregroundColor(.secondary)
                                    }
                                    Text(alert.timeAgoString)
                                        .font(.caption2)
                                        .foregroundColor(.secondary)
                                }
                            }
                            if relatedAlerts.count > 10 {
                                Text("+ \(relatedAlerts.count - 10) more")
                                    .font(.caption2).foregroundColor(.secondary)
                            }
                        }
                    }

                    // Action buttons
                    HStack(spacing: 12) {
                        if let onDismiss {
                            Button {
                                onDismiss()
                            } label: {
                                Label(String(localized: "campaigns.dismiss", defaultValue: "Dismiss"), systemImage: "checkmark.circle")
                            }
                            .controlSize(.small)
                            .help("Mark this campaign as reviewed and hide it")
                        }
                        if let onRestore {
                            Button {
                                onRestore()
                            } label: {
                                Label(String(localized: "campaigns.restore", defaultValue: "Restore"), systemImage: "arrow.uturn.backward")
                            }
                            .controlSize(.small)
                        }
                        Spacer()
                        Button {
                            let text = "Campaign: \(campaign.ruleTitle)\nType: \(campaignType)\nSeverity: \(campaign.severity.label)\nTime: \(campaign.dateTimeString)\n\n\(campaign.description)\n\nTactics: \(campaign.mitreTechniques)\n\nGuidance:\n\(guidance.map { "• \($0.text)" }.joined(separator: "\n"))"
                            NSPasteboard.general.clearContents()
                            NSPasteboard.general.setString(text, forType: .string)
                        } label: {
                            Label(String(localized: "action.copy", defaultValue: "Copy Details"), systemImage: "doc.on.doc")
                        }
                        .controlSize(.small)
                    }
                    .padding(.top, 4)
                }
            }
            .padding(4)
        }
        .accessibilityElement(children: .combine)
    }
}
