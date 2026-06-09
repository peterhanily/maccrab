// V2MockDataProvider.swift
// Phase 4: returns the V2MockRepository fixtures verbatim.
// Used as the default provider until V2LiveDataProvider succeeds.

import Foundation

@MainActor
public final class V2MockDataProvider: V2DataProvider {
    public let mode: V2DataSourceMode = .mock
    public let lastErrorDescription: String? = nil
    public let dataDir: String? = nil

    public init() {}

    public func alerts(since: Date, limit: Int) async -> [V2MockAlert] {
        Array(V2MockRepository.alerts.filter { $0.timestamp >= since }.prefix(limit))
    }
    public func events(limit: Int) async -> [V2MockEvent] {
        Array(V2MockRepository.events.prefix(limit))
    }
    public func campaigns(since: Date, limit: Int) async -> [V2MockCampaign] {
        Array(V2MockRepository.campaigns.filter { $0.lastSeen >= since }.prefix(limit))
    }
    public func traces(limit: Int) async -> [V2MockTrace] {
        Array(V2MockRepository.traces.prefix(limit))
    }
    public func rules() async -> [V2MockRule]                  { V2MockRepository.rules }
    public func feeds() async -> [V2MockFeed]                  { V2MockRepository.feeds }
    public func mcpServers() async -> [V2MockMCP]              { V2MockRepository.mcpServers }
    public func collectors() async -> [V2MockCollector]        { V2MockRepository.collectors }
    public func permissions() async -> [V2MockPermission]      { V2MockRepository.permissions }
    public func packages() async -> [V2MockPackage]            { V2MockRepository.packages }
    public func extensions() async -> [V2MockExtension]        { V2MockRepository.extensions }

    // Mutations are no-ops in mock mode — there's nothing persistent
    // to update. Return success so the UI shows expected feedback.
    public func suppressAlert(id: String) async -> Bool { true }
    public func unsuppressAlert(id: String) async -> Bool { true }
    public func deleteAlert(id: String) async -> Bool { true }
    public func suppressAlerts(ids: [String]) async -> Int { ids.count }
    public func suppressCampaign(id: String) async -> Int { 1 }
    public func refreshThreatIntel() async -> Bool { true }
    public func suppressions() async -> [V2SuppressionEntry] { [] }
    public func liftSuppression(ruleId: String, scope: String) async -> Bool { true }
    public func traceMembers(traceId: String) async -> [V2TraceMember] { [] }

    public func heartbeat() async -> V2HeartbeatSnapshot? { nil }

    public func alertHistogram(rangeKey: String) async -> [V2OverviewBucket] {
        // Re-use the procedural mock buckets so non-live mode looks
        // populated for screenshots / dev work.
        V2MockHistogramFactory.synthBuckets(rangeKey: rangeKey)
    }

    public func kpis() async -> V2OverviewKPIs {
        V2OverviewKPIs(
            openAlerts24h: V2MockRepository.alerts.filter { !$0.suppressed }.count,
            openAlertsLast24hDelta: 24,
            activeCampaigns: V2MockRepository.campaigns.count,
            activeCampaignsCritical: V2MockRepository.campaigns.filter { $0.severity == .critical }.count,
            activeCampaignsHigh: V2MockRepository.campaigns.filter { $0.severity == .high }.count,
            activeCampaignsMedium: V2MockRepository.campaigns.filter { $0.severity == .medium }.count,
            eventsPerSecond: 1700,
            eventsLast8Buckets: [2.0, 2.2, 2.5, 2.1, 2.4, 2.6, 2.3, 2.4]
        )
    }
}
