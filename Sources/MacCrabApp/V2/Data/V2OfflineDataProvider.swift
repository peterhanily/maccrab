// V2OfflineDataProvider.swift
// MacCrabApp — Dashboard v2
//
// The honest empty/offline data provider. The dashboard starts on this (in a
// release build) and reverts to it when `connectLiveData()` finds no on-disk
// daemon stores — fresh install, System Extension not yet approved, pre-boot.
//
// Every accessor returns EMPTY / zeroed data. Unlike V2MockDataProvider (which
// serves fabricated [DEMO] fixtures and is DEBUG-only), this provider renders
// ZERO fake/sample/demo content, so a release build never shows invented
// alerts, campaigns, traces, or KPIs. The workspaces' "Protection inactive" /
// empty-state copy carries the user-facing signal; the data itself is just
// empty until live data connects.

import Foundation

@MainActor
public final class V2OfflineDataProvider: V2DataProvider {
    public let mode: V2DataSourceMode = .offline
    public let lastErrorDescription: String? = nil
    public let dataDir: String? = nil

    public init() {}

    public func alerts(since: Date, limit: Int) async -> [V2MockAlert] { [] }
    public func events(limit: Int) async -> [V2MockEvent] { [] }
    public func campaigns(since: Date, limit: Int) async -> [V2MockCampaign] { [] }
    public func traces(limit: Int) async -> [V2MockTrace] { [] }
    public func rules() async -> [V2MockRule] { [] }
    public func feeds() async -> [V2MockFeed] { [] }
    public func mcpServers() async -> [V2MockMCP] { [] }
    public func collectors() async -> [V2MockCollector] { [] }
    public func permissions() async -> [V2MockPermission] { [] }
    public func packages() async -> [V2MockPackage] { [] }
    public func extensions() async -> [V2MockExtension] { [] }

    // Mutations: nothing to mutate offline — report no-op (no rows touched).
    public func suppressAlert(id: String) async -> Bool { false }
    public func unsuppressAlert(id: String) async -> Bool { false }
    public func deleteAlert(id: String) async -> Bool { false }
    public func suppressAlerts(ids: [String]) async -> Int { 0 }
    public func suppressCampaign(id: String) async -> Int { 0 }
    public func refreshThreatIntel() async -> Bool { false }
    public func suppressions() async -> [V2SuppressionEntry] { [] }
    public func liftSuppression(ruleId: String, scope: String) async -> Bool { false }
    public func traceMembers(traceId: String) async -> [V2TraceMember] { [] }

    public func heartbeat() async -> V2HeartbeatSnapshot? { nil }
    public func alertHistogram(rangeKey: String) async -> [V2OverviewBucket] { [] }
    public func kpis() async -> V2OverviewKPIs { .zero }
}
