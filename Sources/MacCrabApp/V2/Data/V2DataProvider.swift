// V2DataProvider.swift
// MacCrabApp — Dashboard v2
//
// Phase 4: data provider abstraction.
//
// Workspaces fetch via this protocol so the same view code runs
// against either MacCrabCore stores (live) or the V2MockRepository
// fixtures (when no daemon has run on this machine yet).
//
// Live mode is best-effort: any per-call failure (DB missing,
// schema mismatch, etc.) is reported via `lastErrorDescription`
// and the call returns whatever is available — usually an empty
// array, occasionally the mock fallback for that surface.

import Foundation

public enum V2DataSourceMode: String, Sendable, Equatable {
    case mock
    case live

    public var label: String {
        switch self {
        case .mock: return "Mock"
        case .live: return "Live"
        }
    }
}

@MainActor
public protocol V2DataProvider: AnyObject {
    var mode: V2DataSourceMode { get }
    var lastErrorDescription: String? { get }

    /// Diagnostic — which DB directory (if any) the live provider opened.
    var dataDir: String? { get }

    func alerts(limit: Int) async -> [V2MockAlert]
    func events(limit: Int) async -> [V2MockEvent]
    func campaigns(limit: Int) async -> [V2MockCampaign]
    func traces(limit: Int) async -> [V2MockTrace]
    func rules() async -> [V2MockRule]

    /// Composite (sequence + graph) rule id → display title. These
    /// live in `compiled_rules/{sequences,graph}/`, are evaluated by
    /// separate engines, and so NEVER appear in `rules()` (single-event
    /// Sigma only). An alert deep-links its ruleId into the Detection
    /// rule-search box; for a composite-rule id that lands on an empty
    /// table, so the workspace uses this map to explain why instead of
    /// showing a blank list. Keys are LOWERCASED to match the
    /// workspace's lowercased query. Defaults to empty (mock provider).
    func compositeRuleLabels() async -> [String: String]

    func feeds() async -> [V2MockFeed]
    func mcpServers() async -> [V2MockMCP]
    func collectors() async -> [V2MockCollector]
    func permissions() async -> [V2MockPermission]
    func packages() async -> [V2MockPackage]
    func extensions() async -> [V2MockExtension]

    /// v1.11.1 (M2 backlog): operator-configured external sinks
    /// (webhooks, SIEM endpoints, file outputs, object stores).
    /// Empty when no daemon_config.json / notifications.json exists.
    func integrations() async -> [V2MockIntegration]

    /// Optional rich heartbeat written by the daemon. Returns nil if
    /// the heartbeat file is missing (daemon not running) or stale
    /// (>5 minutes old).
    func heartbeat() async -> V2HeartbeatSnapshot?

    /// KPI snapshot for the Overview workspace. Empty (zeroed) when
    /// no daemon data is available.
    func kpis() async -> V2OverviewKPIs

    /// Severity-bucketed alert histogram for the Overview chart.
    /// `rangeKey` is one of "1h" / "6h" / "24h" / "7d".
    func alertHistogram(rangeKey: String) async -> [V2OverviewBucket]

    // MARK: - Mutations

    /// Suppress a single alert. Returns true on success.
    func suppressAlert(id: String) async -> Bool

    /// Lift a previously-applied suppression on a single alert by id.
    /// Used by the History tab's "Unsuppress" row action. Returns
    /// true on success.
    func unsuppressAlert(id: String) async -> Bool

    /// Permanently delete a single alert by id. Used by the History
    /// tab's "Delete" row action. Returns true on success.
    func deleteAlert(id: String) async -> Bool

    /// Bulk-suppress alerts. Returns the number of rows actually
    /// updated (could be less than `ids.count` if some IDs don't
    /// exist in the live store).
    func suppressAlerts(ids: [String]) async -> Int

    /// Suppress a campaign and every contributing alert. Returns the
    /// number of items suppressed (the campaign itself + contributors).
    /// Returns 0 on read-only DB / missing campaign.
    func suppressCampaign(id: String) async -> Int

    /// Trigger a one-shot threat-intel feed refresh. Implementations
    /// shell out to `maccrabctl intel refresh` (which signals the
    /// daemon's ThreatIntelFeed actor to call `refreshNow`). Returns
    /// true on success, false on missing CLI or non-zero exit.
    func refreshThreatIntel() async -> Bool

    /// Read live suppression entries from the daemon's
    /// `suppressions.json`. Empty when none exist or no daemon.
    func suppressions() async -> [V2SuppressionEntry]

    /// Lift (remove) a single suppression entry. Pass the ruleId; if
    /// `scope` is non-empty and not "any", the CLI removes the
    /// (rule, scope) pair specifically; otherwise all suppressions
    /// for the rule are lifted. Returns true on success.
    func liftSuppression(ruleId: String, scope: String) async -> Bool

    /// Resolve a trace's member entities for the in-dashboard graph
    /// view. Empty when the trace has no members or the causal graph
    /// store isn't reachable.
    func traceMembers(traceId: String) async -> [V2TraceMember]
}

/// One node in a trace — minimum viable graph representation. The
/// dashboard renders these as a list with entity-type icons; future
/// work upgrades to an actual graph layout but this list-view at
/// least gives operators something more useful than a CLI hint.
public struct V2TraceMember: Identifiable, Sendable, Hashable {
    public let id: String
    public let entityType: String     // "process" / "file" / "network" / "ai_agent" / "persistence"
    public let displayName: String
    public let firstSeen: Date
    public let isAnchor: Bool
    public init(id: String, entityType: String, displayName: String,
                firstSeen: Date, isAnchor: Bool) {
        self.id = id
        self.entityType = entityType
        self.displayName = displayName
        self.firstSeen = firstSeen
        self.isAnchor = isAnchor
    }
}

/// Read-only suppression entry surfaced to the dashboard.
public struct V2SuppressionEntry: Identifiable, Sendable, Hashable {
    public let id: String
    public let ruleId: String
    public let scope: String
    public let addedBy: String
    public let createdAt: Date
    public let expiresAt: Date?
    public init(id: String, ruleId: String, scope: String,
                addedBy: String, createdAt: Date, expiresAt: Date?) {
        self.id = id
        self.ruleId = ruleId
        self.scope = scope
        self.addedBy = addedBy
        self.createdAt = createdAt
        self.expiresAt = expiresAt
    }
}

public struct V2OverviewBucket: Sendable, Equatable, Identifiable {
    public let id = UUID()
    public let start: Date
    public let end: Date
    public let critical: Int
    public let high: Int
    public let medium: Int
    public let low: Int

    public var total: Int { critical + high + medium + low }

    public init(start: Date, end: Date, critical: Int, high: Int, medium: Int, low: Int) {
        self.start = start
        self.end = end
        self.critical = critical
        self.high = high
        self.medium = medium
        self.low = low
    }
}

public struct V2OverviewKPIs: Sendable, Equatable {
    public let openAlerts24h: Int
    public let openAlertsLast24hDelta: Int
    public let activeCampaigns: Int
    public let activeCampaignsCritical: Int
    public let activeCampaignsHigh: Int
    public let activeCampaignsMedium: Int
    public let eventsPerSecond: Double
    public let eventsLast8Buckets: [Double]

    public static let zero = V2OverviewKPIs(
        openAlerts24h: 0, openAlertsLast24hDelta: 0,
        activeCampaigns: 0, activeCampaignsCritical: 0,
        activeCampaignsHigh: 0, activeCampaignsMedium: 0,
        eventsPerSecond: 0, eventsLast8Buckets: []
    )
}

// MARK: - Convenience defaults

extension V2DataProvider {
    public func alerts() async -> [V2MockAlert]      { await alerts(limit: 200) }
    public func events() async -> [V2MockEvent]      { await events(limit: 200) }
    public func campaigns() async -> [V2MockCampaign] { await campaigns(limit: 50) }
    public func traces() async -> [V2MockTrace]      { await traces(limit: 50) }
    /// Default integrations to empty — keeps `V2MockDataProvider`
    /// from needing a no-op override.
    public func integrations() async -> [V2MockIntegration] { [] }
    /// Default to empty — only the live provider reads the on-disk
    /// sequence/graph rule files.
    public func compositeRuleLabels() async -> [String: String] { [:] }
}
