// CampaignView.swift
// MacCrabApp
//
// Shows detected campaigns — kill chains, alert storms, AI compromise,
// and coordinated attacks identified by the campaign detector.

import SwiftUI

struct CampaignView: View {
    @ObservedObject var appState: AppState

    /// Campaign data from alerts with campaign-related rule titles.
    var campaigns: [AlertViewModel] {
        appState.dashboardAlerts.filter { alert in
            let title = alert.ruleTitle
            return title.contains("Campaign") || title.contains("Kill Chain") ||
                title.contains("Alert Storm") || title.contains("Compromise") ||
                title.contains("Coordinated") || title.contains("Lateral")
        }
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                // Header
                HStack {
                    Text(String(localized: "campaigns.title", defaultValue: "Campaigns & Incidents"))
                        .font(.title2).fontWeight(.bold)
                    Spacer()
                    Text("\(campaigns.count) \(String(localized: "campaigns.detected", defaultValue: "detected"))")
                        .font(.subheadline)
                        .foregroundColor(.secondary)
                }
                .padding(.horizontal)
                .padding(.top)

                Text(String(localized: "campaigns.description", defaultValue: "Campaigns are higher-order detections that chain multiple alerts into attack patterns — kill chains, alert storms, AI compromise, and coordinated attacks."))
                    .font(.subheadline)
                    .foregroundColor(.secondary)
                    .padding(.horizontal)

                if campaigns.isEmpty {
                    VStack(spacing: 12) {
                        Spacer()
                        Image(systemName: "shield.checkered")
                            .font(.system(size: 48))
                            .foregroundColor(.secondary.opacity(0.5))
                        Text(String(localized: "campaigns.none", defaultValue: "No campaigns detected"))
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
                            CampaignCard(campaign: campaign)
                        }
                    }
                    .padding(.horizontal)
                }

                Spacer()
            }
        }
        .navigationTitle("Campaigns")
    }
}

struct CampaignCard: View {
    let campaign: AlertViewModel

    var body: some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 8) {
                HStack {
                    Circle()
                        .fill(campaign.severityColor)
                        .frame(width: 10, height: 10)
                    Text(campaign.ruleTitle)
                        .font(.headline)
                    Spacer()
                    Text(campaign.timeAgoString)
                        .font(.caption)
                        .foregroundColor(.secondary)
                }

                Text(campaign.description)
                    .font(.subheadline)
                    .foregroundColor(.secondary)
                    .lineLimit(3)

                if !campaign.mitreTechniques.isEmpty {
                    HStack(spacing: 4) {
                        Image(systemName: "shield.fill")
                            .font(.caption)
                            .foregroundColor(.orange)
                        Text(campaign.mitreTechniques)
                            .font(.caption)
                            .foregroundColor(.orange)
                    }
                }
            }
            .padding(4)
        }
    }
}
