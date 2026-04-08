// CampaignDetector.swift
// MacCrabCore
//
// Meta-alert engine that chains individual alerts into higher-level
// campaign detections. Operates on the alert stream (not raw events)
// and surfaces kill chains, alert storms, AI tool compromise attempts,
// coordinated process attacks, and lateral movement indicators.

import Foundation
import os.log

/// Detects multi-alert campaigns — higher-order attack patterns that
/// emerge from correlating individual detection alerts over time.
///
/// **Level 4 Detection Patterns:**
/// - Kill Chain: multiple MITRE ATT&CK tactics in a time window
/// - Alert Storm: same rule fires excessively (scan / brute-force)
/// - AI Compromise: convergence of AI Guard alerts
/// - Coordinated Attack: single process lineage spans multiple tactics
/// - Lateral Movement: alerts from multiple user contexts
public actor CampaignDetector {

    private let logger = Logger(subsystem: "com.maccrab", category: "campaigns")

    // MARK: - Types

    /// A detected campaign — a higher-order pattern composed of multiple alerts.
    public struct Campaign: Identifiable, Sendable {
        public let id: String
        public let type: CampaignType
        public let severity: Severity
        public let title: String
        public let description: String
        public let alerts: [AlertSummary]
        public let tactics: Set<String>
        public let timeSpanSeconds: Double
        public let detectedAt: Date
    }

    /// The kind of campaign pattern that was detected.
    public enum CampaignType: String, Sendable {
        case killChain = "kill_chain"
        case alertStorm = "alert_storm"
        case aiCompromise = "ai_compromise"
        case coordinatedAttack = "coordinated_attack"
        case lateralMovement = "lateral_movement"
    }

    /// Lightweight summary of a contributing alert, kept in the campaign for drill-down.
    public struct AlertSummary: Sendable {
        public let ruleId: String
        public let ruleTitle: String
        public let severity: Severity
        public let processPath: String?
        public let pid: Int?
        public let userId: String?
        public let timestamp: Date
        public let tactics: Set<String>

        public init(
            ruleId: String,
            ruleTitle: String,
            severity: Severity,
            processPath: String? = nil,
            pid: Int? = nil,
            userId: String? = nil,
            timestamp: Date = Date(),
            tactics: Set<String> = []
        ) {
            self.ruleId = ruleId
            self.ruleTitle = ruleTitle
            self.severity = severity
            self.processPath = processPath
            self.pid = pid
            self.userId = userId
            self.timestamp = timestamp
            self.tactics = tactics
        }
    }

    // MARK: - Configuration

    /// Window for correlating alerts into kill-chain / AI-compromise campaigns.
    private let campaignWindow: TimeInterval

    /// Number of same-rule alerts in `stormWindow` to trigger a high-severity storm.
    private let stormThreshold: Int

    /// Number of same-rule alerts in `stormWindow` to escalate to critical.
    private let stormCriticalThreshold: Int

    /// Time window for alert-storm counting.
    private let stormWindow: TimeInterval

    /// Minimum distinct MITRE tactics to declare a generic kill chain.
    private let minTacticsForKillChain: Int

    /// Hard cap on `recentAlerts`. When exceeded the oldest entries are evicted
    /// (with index decrements) before time-based purging runs. Prevents unbounded
    /// growth during alert storms (e.g. 1k alerts/s × 600s = 600k entries).
    private let maxRecentAlerts: Int

    // MARK: - State

    /// Rolling window of recent alerts for pattern detection.
    private var recentAlerts: [AlertSummary] = []

    /// Per-rule timestamps for storm detection.
    private var ruleAlertCounts: [String: [Date]] = [:]

    /// Recently emitted campaigns keyed by dedup key → detection time.
    private var emittedCampaigns: [String: Date] = [:]

    /// Detected campaigns (kept for `activeCampaigns` queries).
    private var detectedCampaigns: [Campaign] = []

    /// Incremental tactic index: normalized tactic → count of alerts in the
    /// current window that carry that tactic. Maintained in lock-step with
    /// `recentAlerts` via `addToIndexes` / `removeFromIndexes`. Allows
    /// `checkKillChain()` to run in O(T) (number of unique tactics) rather
    /// than O(n·t) (alerts × tactics per alert).
    private var normalizedTacticCounts: [String: Int] = [:]

    /// Incremental user-ID index: user ID → count of alerts in the current
    /// window from that user context. Allows `checkLateralMovement()` to run
    /// in O(1) rather than O(n).
    private var userIdCounts: [String: Int] = [:]

    /// Don't re-emit the same campaign type within this window.
    private let campaignDedupWindow: TimeInterval

    // MARK: - Initialization

    public init(
        campaignWindow: TimeInterval = 600,
        stormThreshold: Int = 10,
        stormCriticalThreshold: Int = 50,
        stormWindow: TimeInterval = 300,
        minTacticsForKillChain: Int = 3,
        maxRecentAlerts: Int = 50_000,
        campaignDedupWindow: TimeInterval = 600
    ) {
        self.campaignWindow = campaignWindow
        self.stormThreshold = stormThreshold
        self.stormCriticalThreshold = stormCriticalThreshold
        self.stormWindow = stormWindow
        self.minTacticsForKillChain = minTacticsForKillChain
        self.maxRecentAlerts = maxRecentAlerts
        self.campaignDedupWindow = campaignDedupWindow
    }

    // MARK: - Public API

    /// Process an alert and check if it triggers any campaign-level detections.
    /// Returns an array of newly detected campaigns (usually 0 or 1).
    public func processAlert(_ alert: AlertSummary) -> [Campaign] {
        recentAlerts.append(alert)
        addToIndexes(alert)
        recordForStormDetection(alert)
        evictExcessAlerts()
        purgeStaleAlerts()

        var campaigns: [Campaign] = []

        if let storm = checkAlertStorm(latestAlert: alert) {
            campaigns.append(storm)
        }
        if let killChain = checkKillChain() {
            campaigns.append(killChain)
        }
        if let aiCompromise = checkAICompromise() {
            campaigns.append(aiCompromise)
        }
        if let coordinated = checkCoordinatedAttack(latestAlert: alert) {
            campaigns.append(coordinated)
        }
        if let lateral = checkLateralMovement() {
            campaigns.append(lateral)
        }

        let novel = campaigns.filter { !isDuplicate($0) }
        for campaign in novel {
            markEmitted(campaign)
            detectedCampaigns.append(campaign)
            logger.warning("Campaign detected: \(campaign.title) [\(campaign.type.rawValue)] severity=\(campaign.severity.rawValue)")
        }
        return novel
    }

    /// Get all active (non-stale) campaigns detected within the campaign window.
    public func activeCampaigns() -> [Campaign] {
        let cutoff = Date().addingTimeInterval(-campaignWindow)
        return detectedCampaigns.filter { $0.detectedAt > cutoff }
    }

    /// Periodic cleanup of stale data.
    public func sweep() {
        purgeStaleAlerts()
        purgeStaleStormCounts()
        purgeStaleCampaigns()
        purgeStaleDedup()
    }

    // MARK: - Storm Detection

    private func recordForStormDetection(_ alert: AlertSummary) {
        ruleAlertCounts[alert.ruleId, default: []].append(alert.timestamp)
    }

    private func checkAlertStorm(latestAlert: AlertSummary) -> Campaign? {
        let ruleId = latestAlert.ruleId
        guard let timestamps = ruleAlertCounts[ruleId] else { return nil }

        let cutoff = latestAlert.timestamp.addingTimeInterval(-stormWindow)
        let recentTimestamps = timestamps.filter { $0 > cutoff }
        let count = recentTimestamps.count

        guard count >= stormThreshold else { return nil }

        let isCritical = count >= stormCriticalThreshold
        let severity: Severity = isCritical ? .critical : .high
        let ratePerMinute = Double(count) / (stormWindow / 60.0)
        let title = isCritical
            ? "Alert Storm: active attack in progress"
            : "Alert Storm: possible scan or brute force"
        let description = "Rule \"\(latestAlert.ruleTitle)\" (\(ruleId)) fired \(count) times in \(Int(stormWindow))s (~\(String(format: "%.1f", ratePerMinute))/min)"

        let stormAlerts = recentAlerts.filter { $0.ruleId == ruleId && $0.timestamp > cutoff }
        let span = timeSpan(of: stormAlerts)

        return Campaign(
            id: makeCampaignId(),
            type: .alertStorm,
            severity: severity,
            title: title,
            description: description,
            alerts: stormAlerts,
            tactics: aggregateTactics(stormAlerts),
            timeSpanSeconds: span,
            detectedAt: Date()
        )
    }

    // MARK: - Kill Chain Detection

    /// Known MITRE tactic prefixes to normalize.
    private static let tacticNormalization: [String: String] = [
        "attack.initial_access": "initial_access",
        "attack.execution": "execution",
        "attack.persistence": "persistence",
        "attack.credential_access": "credential_access",
        "attack.command_and_control": "command_and_control",
        "attack.exfiltration": "exfiltration",
        "attack.defense_evasion": "defense_evasion",
        "attack.privilege_escalation": "privilege_escalation",
        "attack.lateral_movement": "lateral_movement",
        "attack.discovery": "discovery",
        "attack.collection": "collection",
        "attack.impact": "impact",
    ]

    /// High-value 2-tactic combinations that always trigger a kill chain.
    private static let twoTacticCombinations: [Set<String>: (title: String, severity: Severity)] = [
        Set(["initial_access", "persistence"]):
            ("Malware Installation Chain", .high),
        Set(["credential_access", "command_and_control"]):
            ("Full Kill Chain", .critical),
        Set(["persistence", "command_and_control"]):
            ("Full Kill Chain", .critical),
        Set(["initial_access", "execution"]):
            ("Malware Installation Chain", .high),
    ]

    private func normalizeTactic(_ tactic: String) -> String {
        if let normalized = Self.tacticNormalization[tactic] {
            return normalized
        }
        // Strip "attack." prefix if present
        if tactic.hasPrefix("attack.") {
            return String(tactic.dropFirst("attack.".count))
        }
        return tactic
    }

    private func checkKillChain() -> Campaign? {
        // Use the incremental tactic index — O(T) where T = unique tactic count,
        // not O(n·t). `recentAlerts` is already trimmed to the campaign window
        // by `purgeStaleAlerts()`, so no redundant filtering is needed.
        let allTactics = Set(normalizedTacticCounts.keys)
        guard allTactics.count >= 2 else { return nil }

        // Check specific 2-tactic combos first
        for (combo, result) in Self.twoTacticCombinations {
            if combo.isSubset(of: allTactics) {
                let description = "Detected tactics: \(allTactics.sorted().joined(separator: ", ")) across \(recentAlerts.count) alerts within \(Int(campaignWindow))s"
                return Campaign(
                    id: makeCampaignId(),
                    type: .killChain,
                    severity: result.severity,
                    title: result.title,
                    description: description,
                    alerts: recentAlerts,
                    tactics: allTactics,
                    timeSpanSeconds: timeSpan(of: recentAlerts),
                    detectedAt: Date()
                )
            }
        }

        // Generic: 3+ distinct tactics → multi-stage attack
        if allTactics.count >= minTacticsForKillChain {
            let title: String
            let severity: Severity
            let hasInitialAccess = allTactics.contains("initial_access")
            let hasExecution = allTactics.contains("execution")
            let hasPersistence = allTactics.contains("persistence")
            let hasCredentialAccess = allTactics.contains("credential_access")
            let hasC2 = allTactics.contains("command_and_control")

            if hasCredentialAccess && hasPersistence && hasC2 {
                title = "Full Kill Chain"
                severity = .critical
            } else if hasInitialAccess && hasExecution && hasPersistence {
                title = "Malware Installation Chain"
                severity = .high
            } else {
                title = "Multi-Stage Attack"
                severity = .critical
            }

            let description = "Detected \(allTactics.count) tactics: \(allTactics.sorted().joined(separator: ", ")) across \(recentAlerts.count) alerts within \(Int(campaignWindow))s"
            return Campaign(
                id: makeCampaignId(),
                type: .killChain,
                severity: severity,
                title: title,
                description: description,
                alerts: recentAlerts,
                tactics: allTactics,
                timeSpanSeconds: timeSpan(of: recentAlerts),
                detectedAt: Date()
            )
        }

        return nil
    }

    // MARK: - AI Compromise Detection

    /// AI Guard rule ID prefix.
    private static let aiGuardPrefix = "maccrab.ai-guard."

    /// Extract the AI Guard category from a rule ID (e.g. "maccrab.ai-guard.credential-access" → "credential-access").
    private func aiGuardCategory(from ruleId: String) -> String? {
        guard ruleId.hasPrefix(Self.aiGuardPrefix) else { return nil }
        let category = String(ruleId.dropFirst(Self.aiGuardPrefix.count))
        // Collapse mcp-* subcategories into "mcp"
        if category.hasPrefix("mcp-") || category == "mcp" {
            return "mcp"
        }
        return category
    }

    /// Known 2-category combos that always trigger AI compromise.
    private static let aiTwoCategoryCombos: [Set<String>: String] = [
        Set(["credential-access", "boundary-violation"]):
            "AI Tool Compromise Attempt",
        Set(["network-sandbox", "prompt-injection"]):
            "AI Tool Exploitation Chain",
    ]

    /// Check if an alert represents a compound prompt injection threat.
    /// Compound threats from forensicate indicate multi-vector injection attacks
    /// and should be weighted more heavily in campaign detection.
    private func isCompoundPromptInjection(_ alert: AlertSummary) -> Bool {
        alert.ruleId == "maccrab.ai-guard.prompt-injection"
            && alert.ruleTitle.localizedCaseInsensitiveContains("compound")
    }

    private func checkAICompromise() -> Campaign? {
        let cutoff = Date().addingTimeInterval(-campaignWindow)
        let aiAlerts = recentAlerts.filter {
            $0.timestamp > cutoff && $0.ruleId.hasPrefix(Self.aiGuardPrefix)
        }
        guard aiAlerts.count >= 2 else { return nil }

        // Collect distinct AI Guard categories.
        // Compound prompt injection threats (multi-vector attacks detected by
        // forensicate) count as 2 categories: the original "prompt-injection"
        // plus a synthetic "prompt-injection-compound" category, reflecting
        // their higher severity as a multi-vector indicator.
        var categories = Set<String>()
        for alert in aiAlerts {
            if let cat = aiGuardCategory(from: alert.ruleId) {
                categories.insert(cat)
                if isCompoundPromptInjection(alert) {
                    categories.insert("prompt-injection-compound")
                }
            }
        }

        guard categories.count >= 2 else { return nil }

        // Check specific 2-category combos
        for (combo, title) in Self.aiTwoCategoryCombos {
            if combo.isSubset(of: categories) {
                let description = "AI Guard categories: \(categories.sorted().joined(separator: ", ")) across \(aiAlerts.count) alerts"
                return Campaign(
                    id: makeCampaignId(),
                    type: .aiCompromise,
                    severity: .critical,
                    title: title,
                    description: description,
                    alerts: aiAlerts,
                    tactics: aggregateTactics(aiAlerts),
                    timeSpanSeconds: timeSpan(of: aiAlerts),
                    detectedAt: Date()
                )
            }
        }

        // Generic: 3+ AI Guard categories
        if categories.count >= 3 {
            let description = "AI Guard categories: \(categories.sorted().joined(separator: ", ")) across \(aiAlerts.count) alerts within \(Int(campaignWindow))s"
            return Campaign(
                id: makeCampaignId(),
                type: .aiCompromise,
                severity: .critical,
                title: "AI Tool Under Attack",
                description: description,
                alerts: aiAlerts,
                tactics: aggregateTactics(aiAlerts),
                timeSpanSeconds: timeSpan(of: aiAlerts),
                detectedAt: Date()
            )
        }

        return nil
    }

    // MARK: - Coordinated Attack Detection

    private func checkCoordinatedAttack(latestAlert: AlertSummary) -> Campaign? {
        let cutoff = Date().addingTimeInterval(-campaignWindow)
        let windowAlerts = recentAlerts.filter { $0.timestamp > cutoff }

        // Group by PID — alerts from same process spanning multiple tactics
        if let pid = latestAlert.pid {
            let pidAlerts = windowAlerts.filter { $0.pid == pid }
            let pidTactics = aggregateNormalizedTactics(pidAlerts)

            if pidTactics.count >= 3 {
                let description = "Process PID \(pid) triggered alerts spanning \(pidTactics.count) tactics: \(pidTactics.sorted().joined(separator: ", "))"
                return Campaign(
                    id: makeCampaignId(),
                    type: .coordinatedAttack,
                    severity: .critical,
                    title: "Persistent Threat Actor",
                    description: description,
                    alerts: pidAlerts,
                    tactics: pidTactics,
                    timeSpanSeconds: timeSpan(of: pidAlerts),
                    detectedAt: Date()
                )
            }

            if pidTactics.count >= 2 {
                let description = "Process PID \(pid) triggered alerts spanning \(pidTactics.count) tactics: \(pidTactics.sorted().joined(separator: ", "))"
                return Campaign(
                    id: makeCampaignId(),
                    type: .coordinatedAttack,
                    severity: .high,
                    title: "Coordinated Attack from single process",
                    description: description,
                    alerts: pidAlerts,
                    tactics: pidTactics,
                    timeSpanSeconds: timeSpan(of: pidAlerts),
                    detectedAt: Date()
                )
            }
        }

        // Group by process path — alerts from same executable spanning multiple tactics
        if let path = latestAlert.processPath {
            let pathAlerts = windowAlerts.filter { $0.processPath == path }
            let pathTactics = aggregateNormalizedTactics(pathAlerts)

            if pathTactics.count >= 3 {
                let lastComponent = (path as NSString).lastPathComponent
                let description = "Process \(lastComponent) (\(path)) triggered alerts spanning \(pathTactics.count) tactics: \(pathTactics.sorted().joined(separator: ", "))"
                return Campaign(
                    id: makeCampaignId(),
                    type: .coordinatedAttack,
                    severity: .critical,
                    title: "Persistent Threat Actor",
                    description: description,
                    alerts: pathAlerts,
                    tactics: pathTactics,
                    timeSpanSeconds: timeSpan(of: pathAlerts),
                    detectedAt: Date()
                )
            }

            if pathTactics.count >= 2 {
                let lastComponent = (path as NSString).lastPathComponent
                let description = "Process \(lastComponent) (\(path)) triggered alerts spanning \(pathTactics.count) tactics: \(pathTactics.sorted().joined(separator: ", "))"
                return Campaign(
                    id: makeCampaignId(),
                    type: .coordinatedAttack,
                    severity: .high,
                    title: "Coordinated Attack from single process",
                    description: description,
                    alerts: pathAlerts,
                    tactics: pathTactics,
                    timeSpanSeconds: timeSpan(of: pathAlerts),
                    detectedAt: Date()
                )
            }
        }

        return nil
    }

    // MARK: - Lateral Movement Detection

    private func checkLateralMovement() -> Campaign? {
        // Use the incremental user-ID index — O(1), not O(n).
        guard userIdCounts.count >= 2 else { return nil }
        let userIds = Set(userIdCounts.keys)
        let description = "Alerts from \(userIds.count) user contexts (\(userIds.sorted().joined(separator: ", "))) within \(Int(campaignWindow))s — possible privilege escalation or lateral movement"
        return Campaign(
            id: makeCampaignId(),
            type: .lateralMovement,
            severity: .high,
            title: "Possible Lateral Movement",
            description: description,
            alerts: recentAlerts,
            tactics: aggregateTactics(recentAlerts),
            timeSpanSeconds: timeSpan(of: recentAlerts),
            detectedAt: Date()
        )
    }

    // MARK: - Deduplication

    /// Build a dedup key from campaign type (and rule ID for storms).
    private func dedupKey(for campaign: Campaign) -> String {
        switch campaign.type {
        case .alertStorm:
            // Dedup per-rule for storms
            let ruleId = campaign.alerts.first?.ruleId ?? "unknown"
            return "\(campaign.type.rawValue):\(ruleId)"
        default:
            return campaign.type.rawValue
        }
    }

    private func isDuplicate(_ campaign: Campaign) -> Bool {
        let key = dedupKey(for: campaign)
        guard let lastEmitted = emittedCampaigns[key] else { return false }
        let interval = campaign.detectedAt.timeIntervalSince(lastEmitted)
        // Guard against clock going backward (NTP adjustment, DST): a negative
        // interval must not suppress the new campaign.
        return interval >= 0 && interval < campaignDedupWindow
    }

    private func markEmitted(_ campaign: Campaign) {
        let key = dedupKey(for: campaign)
        emittedCampaigns[key] = campaign.detectedAt
    }

    // MARK: - Helpers

    private func makeCampaignId() -> String {
        "CAMP-\(UUID().uuidString.prefix(8))"
    }

    private func aggregateTactics(_ alerts: [AlertSummary]) -> Set<String> {
        var tactics = Set<String>()
        for alert in alerts {
            tactics.formUnion(alert.tactics)
        }
        return tactics
    }

    private func aggregateNormalizedTactics(_ alerts: [AlertSummary]) -> Set<String> {
        var tactics = Set<String>()
        for alert in alerts {
            for tactic in alert.tactics {
                tactics.insert(normalizeTactic(tactic))
            }
        }
        return tactics
    }

    private func timeSpan(of alerts: [AlertSummary]) -> Double {
        guard let first = alerts.min(by: { $0.timestamp < $1.timestamp }),
              let last = alerts.max(by: { $0.timestamp < $1.timestamp }) else {
            return 0
        }
        return last.timestamp.timeIntervalSince(first.timestamp)
    }

    // MARK: - Incremental Index Helpers

    /// Add a newly appended alert to the tactic and user-ID indexes.
    private func addToIndexes(_ alert: AlertSummary) {
        for tactic in alert.tactics {
            normalizedTacticCounts[normalizeTactic(tactic), default: 0] += 1
        }
        if let uid = alert.userId {
            userIdCounts[uid, default: 0] += 1
        }
    }

    /// Remove a stale alert from the tactic and user-ID indexes.
    private func removeFromIndexes(_ alert: AlertSummary) {
        for tactic in alert.tactics {
            let n = normalizeTactic(tactic)
            if (normalizedTacticCounts[n] ?? 0) <= 1 {
                normalizedTacticCounts.removeValue(forKey: n)
            } else {
                normalizedTacticCounts[n]! -= 1
            }
        }
        if let uid = alert.userId {
            if (userIdCounts[uid] ?? 0) <= 1 {
                userIdCounts.removeValue(forKey: uid)
            } else {
                userIdCounts[uid]! -= 1
            }
        }
    }

    // MARK: - Cleanup

    /// Evict the oldest alerts when the hard cap is exceeded.
    /// Alerts are always appended, so the oldest entries are at the front.
    private func evictExcessAlerts() {
        guard recentAlerts.count > maxRecentAlerts else { return }
        let evictCount = recentAlerts.count - maxRecentAlerts
        let evicted = recentAlerts.prefix(evictCount)
        for alert in evicted {
            removeFromIndexes(alert)
        }
        recentAlerts.removeFirst(evictCount)
        logger.warning("CampaignDetector: evicted \(evictCount) oldest alerts (cap=\(self.maxRecentAlerts))")
    }

    private func purgeStaleAlerts() {
        let cutoff = Date().addingTimeInterval(-campaignWindow)
        // Decrement indexes for stale alerts before removing them from the array,
        // so checkKillChain() and checkLateralMovement() see accurate counts.
        for alert in recentAlerts where alert.timestamp <= cutoff {
            removeFromIndexes(alert)
        }
        recentAlerts.removeAll { $0.timestamp <= cutoff }
    }

    private func purgeStaleStormCounts() {
        let cutoff = Date().addingTimeInterval(-stormWindow)
        for (ruleId, timestamps) in ruleAlertCounts {
            let filtered = timestamps.filter { $0 > cutoff }
            if filtered.isEmpty {
                ruleAlertCounts.removeValue(forKey: ruleId)
            } else {
                ruleAlertCounts[ruleId] = filtered
            }
        }
    }

    private func purgeStaleCampaigns() {
        let cutoff = Date().addingTimeInterval(-86400) // Keep campaigns for 24 hours
        detectedCampaigns.removeAll { $0.detectedAt <= cutoff }
    }

    private func purgeStaleDedup() {
        let now = Date()
        emittedCampaigns = emittedCampaigns.filter { _, date in
            now.timeIntervalSince(date) < campaignDedupWindow
        }
    }
}
