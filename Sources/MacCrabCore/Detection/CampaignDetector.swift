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

        // MARK: - v1.12.6 Wave 2C aggregate attribution

        /// Distinct user IDs across contributing alerts.
        public let affectedUsers: Set<String>

        /// Distinct process executable paths across contributing alerts.
        public let affectedExecutables: Set<String>

        /// Earliest contributing alert timestamp.
        public let firstSeen: Date

        /// Latest contributing alert timestamp.
        public let lastSeen: Date

        /// Max process-ancestor depth observed across contributing alerts.
        public let processTreeDepth: Int

        /// Distinct MITRE ATT&CK technique IDs across contributing alerts.
        public let techniques: Set<String>

        /// Distinct `ai_tool` values (claude_code, cursor, …) involved.
        /// Empty for non-AI campaigns.
        public let aiTools: Set<String>

        public init(
            id: String,
            type: CampaignType,
            severity: Severity,
            title: String,
            description: String,
            alerts: [AlertSummary],
            tactics: Set<String>,
            timeSpanSeconds: Double,
            detectedAt: Date
        ) {
            self.id = id
            self.type = type
            self.severity = severity
            self.title = title
            self.description = description
            self.alerts = alerts
            self.tactics = tactics
            self.timeSpanSeconds = timeSpanSeconds
            self.detectedAt = detectedAt

            // v1.12.6 Wave 2C: compute aggregates from the contributing
            // alerts at construction time. The detector has them in-memory
            // here — no cross-DB join needed at persist time.
            self.affectedUsers = Set(alerts.compactMap { $0.userId })
            self.affectedExecutables = Set(alerts.compactMap { $0.processPath })
            self.firstSeen = alerts.map(\.timestamp).min() ?? detectedAt
            self.lastSeen = alerts.map(\.timestamp).max() ?? detectedAt
            self.processTreeDepth = alerts.compactMap(\.processTreeDepth).max() ?? 0
            self.techniques = Set(alerts.flatMap(\.mitreTechniques))
            self.aiTools = Set(alerts.compactMap(\.aiTool))
        }
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

        // MARK: - v1.12.6 Wave 2C aggregation inputs
        //
        // Optional fields populated by the EventLoop when constructing the
        // summary. Default to empty/nil so existing call sites that don't
        // supply them keep compiling unchanged. The `Campaign` initializer
        // aggregates these across the contributing-alert list at persist
        // time.

        /// MITRE ATT&CK technique IDs from the firing rule (e.g. `["T1059.004"]`).
        public let mitreTechniques: Set<String>

        /// Originating AI tool (claude_code, cursor, …) if the event was
        /// attributed to one. `nil` for non-AI alerts.
        public let aiTool: String?

        /// Depth of the contributing event's process ancestor chain
        /// (`ancestors.count`). Used to surface the deepest lineage observed
        /// during a campaign.
        public let processTreeDepth: Int?

        /// v1.19 (S1-T4): the subject is a trusted signer (notarized
        /// Developer-ID / MacCrab first-party) or an Apple platform binary,
        /// as judged by `NoiseFilter` at the feed site. Used to exclude
        /// LOW/MEDIUM trusted-subject alerts from kill-chain / coordinated-
        /// attack tactic-counting — slow-burn FP campaigns minted on
        /// swiftpm-testing-helper / Xcode helpers. HIGH/CRITICAL trusted
        /// alerts still feed (slow-burn abuse of trusted-signed tooling is
        /// exactly what campaign correlation is for). Defaults `false` so
        /// existing call sites that don't supply it keep their old behavior.
        public let isTrustedSubject: Bool

        public init(
            ruleId: String,
            ruleTitle: String,
            severity: Severity,
            processPath: String? = nil,
            pid: Int? = nil,
            userId: String? = nil,
            timestamp: Date = Date(),
            tactics: Set<String> = [],
            mitreTechniques: Set<String> = [],
            aiTool: String? = nil,
            processTreeDepth: Int? = nil,
            isTrustedSubject: Bool = false
        ) {
            self.ruleId = ruleId
            self.ruleTitle = ruleTitle
            self.severity = severity
            self.processPath = processPath
            self.pid = pid
            self.userId = userId
            self.timestamp = timestamp
            self.tactics = tactics
            self.mitreTechniques = mitreTechniques
            self.aiTool = aiTool
            self.processTreeDepth = processTreeDepth
            self.isTrustedSubject = isTrustedSubject
        }
    }

    /// Bounded-work and conservation counters for the rolling campaign index.
    /// These counters make the detector's hot-path cost and cap behavior
    /// observable without exposing alert contents.
    public struct TelemetrySnapshot: Sendable, Equatable {
        public let acceptedAlerts: UInt64
        public let activeAlerts: Int
        public let peakActiveAlerts: Int
        public let maxRecentAlerts: Int
        public let timeExpiredAlerts: UInt64
        public let capEvictedAlerts: UInt64
        public let indexMutationOperations: UInt64
        public let decisionOperations: UInt64
        public let candidateAlertVisits: UInt64
        public let totalAccountedOperations: UInt64
        public let campaignsMaterialized: UInt64
        public let expirationEntries: Int
        public let ruleKeys: Int
        public let pidKeys: Int
        public let pathKeys: Int
        public let userKeys: Int
        public let tacticKeys: Int
        public let aiCategoryKeys: Int
        public let conservationHolds: Bool
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

    /// Authoritative active-alert table. `activeOrder` preserves the old
    /// append/cap ordering while `expiration` supports exact out-of-order
    /// timestamp expiry in O(log n) per expired entry.
    private var alertsByID: [UInt64: IndexedAlert] = [:]
    private var activeOrder = OrderedIDIndex()
    private var expiration = IndexedExpirationHeap()
    private var nextAlertID: UInt64 = 1

    /// Incremental indexes used by the five campaign evaluators. Values retain
    /// insertion order for exact campaign contributor ordering and support
    /// O(1)-amortized arbitrary removal for time expiry.
    private var ruleAlertIDs: [String: OrderedIDIndex] = [:]
    private var userAlertIDs: [String: OrderedIDIndex] = [:]
    private var rawTacticAlertIDs: [String: OrderedIDIndex] = [:]
    private var normalizedTacticAlertIDs: [String: OrderedIDIndex] = [:]
    private var contributorTacticAlertIDs: [String: OrderedIDIndex] = [:]
    private var aiCategoryAlertIDs: [String: OrderedIDIndex] = [:]
    private var aiAlertIDs = OrderedIDIndex()
    private var tacticContributorIDs = OrderedIDIndex()
    private var tacticContributorCriticalCount = 0
    private var pidGroups: [Int: CoordinatedGroupIndex] = [:]
    private var pathGroups: [String: CoordinatedGroupIndex] = [:]

    /// Per-rule bounded timestamp indexes for storm counting. This state is
    /// intentionally independent of the 5k campaign window, matching the old
    /// detector: cap/time eviction of a campaign contributor did not erase its
    /// storm timestamp before the periodic storm sweep.
    private var stormRules: [String: StormRuleIndex] = [:]
    private var stormExpiration = IndexedExpirationHeap()
    private var stormRuleByID: [UInt64: String] = [:]

    /// Recently emitted campaigns keyed by dedup key → (detection time, the
    /// highest severity emitted for that key within the window). The severity is
    /// tracked so a genuine escalation (e.g. a HIGH coordinated attack becoming
    /// CRITICAL) can re-emit inside the dedup window instead of being swallowed.
    private var emittedCampaigns: [String: (date: Date, severity: Severity)] = [:]

    /// Detected campaigns (kept for `activeCampaigns` queries).
    private var detectedCampaigns: [Campaign] = []

    /// Don't re-emit the same campaign type within this window.
    private let campaignDedupWindow: TimeInterval

    // MARK: - Runtime telemetry

    private var acceptedAlerts: UInt64 = 0
    private var peakActiveAlerts = 0
    private var timeExpiredAlerts: UInt64 = 0
    private var capEvictedAlerts: UInt64 = 0
    private var indexMutationOperations: UInt64 = 0
    private var decisionOperations: UInt64 = 0
    private var candidateAlertVisits: UInt64 = 0
    private var campaignsMaterialized: UInt64 = 0

    private struct IndexedAlert {
        let id: UInt64
        let summary: AlertSummary
        let normalizedTactics: Set<String>
        let aiCategories: Set<String>
        let contributesTactics: Bool
    }

    private enum CandidateSelection {
        case ruleSince(String, Date)
        case tacticContributors
        case aiAlerts
        case pid(Int)
        case path(String)
        case allAlerts
        case summaries([AlertSummary])
    }

    private struct CandidatePlan {
        let type: CampaignType
        let severity: Severity
        let title: String
        let description: String
        let selection: CandidateSelection
        /// `nil` means aggregate the contributors' raw tactic strings.
        let tactics: Set<String>?
        let detectedAt: Date
        let dedupKey: String
    }

    // MARK: - Initialization

    public init(
        campaignWindow: TimeInterval = 600,
        stormThreshold: Int = 10,
        stormCriticalThreshold: Int = 50,
        stormWindow: TimeInterval = 300,
        // v1.6.4: raised from 3 → 4. The old value was trivially hit on
        // developer machines running routine admin commands (ps / lsof
        // for discovery, csrutil status for defense_evasion, curl for
        // exfiltration all within 10 minutes). 4 distinct tactics is
        // a stronger signal while still catching real multi-stage
        // attacks, which typically go discovery → credential_access →
        // persistence → exfiltration (four tactics, by design).
        // v1.12.0: `MACCRAB_DEV_MODE=1` raises this to 5 — on developer
        // machines running `make test-campaign`, lots of legitimate
        // dev activity touches 4 tactics in 10 min. 5 catches real
        // attacks while leaving room for dev workflows.
        minTacticsForKillChain: Int? = nil,
        // v1.6.22: 50_000 → 5_000. Each AlertSummary ~2 KB (paths, tactic
        // sets, timestamps); the old cap allowed ~100 MB resident. Kill-chain
        // detection operates on the recent window (`campaignWindow`, default
        // 10 min) — beyond that the alerts are evicted by time anyway. The
        // larger cap was buying nothing for detection and a lot for memory.
        maxRecentAlerts: Int = 5_000,
        campaignDedupWindow: TimeInterval? = nil
    ) {
        // v1.12.0 post-audit (M-Sec2): MACCRAB_DEV_MODE is honored only
        // on DEBUG builds. Release-build daemons ignore the env var
        // so a root attacker can't lower kill-chain thresholds via
        // launchd plist injection.
        #if DEBUG
        let devMode = Foundation.ProcessInfo.processInfo.environment["MACCRAB_DEV_MODE"] == "1"
        #else
        let devMode = false
        #endif
        self.campaignWindow = campaignWindow
        self.stormThreshold = stormThreshold
        self.stormCriticalThreshold = stormCriticalThreshold
        self.stormWindow = stormWindow
        // v1.12.0 dev-mode gate — when MACCRAB_DEV_MODE=1, raise the
        // kill-chain tactic floor from 4 to 5. The audit observed that
        // developer machines running CI tests, build pipelines, and
        // package-install lineages touch 4 tactics regularly; 5 is
        // closer to a real attack signature.
        self.minTacticsForKillChain = minTacticsForKillChain ?? (devMode ? 5 : 4)
        self.maxRecentAlerts = max(0, maxRecentAlerts)
        // v1.12.0 dev-mode gate — wider dedup window (1200 s = 20 min)
        // when MACCRAB_DEV_MODE=1, so iterative test runs of similar
        // tactic patterns don't generate repeated campaign alerts.
        self.campaignDedupWindow = campaignDedupWindow ?? (devMode ? 1200 : 600)
    }

    // MARK: - Public API

    /// Process an alert and check if it triggers any campaign-level detections.
    /// Returns an array of newly detected campaigns (usually 0 or 1).
    public func processAlert(_ alert: AlertSummary) -> [Campaign] {
        processAlert(alert, evaluatedAt: Date(), useReferenceEvaluator: false)
    }

    /// Deterministic clock seam used by equivalence and churn tests.
    func processAlert(_ alert: AlertSummary, evaluatedAt: Date) -> [Campaign] {
        processAlert(alert, evaluatedAt: evaluatedAt, useReferenceEvaluator: false)
    }

    /// Slow scan-based evaluator seam. It shares only rolling-window
    /// admission/expiry with the production detector, then independently
    /// derives every candidate from the ordered alert set. Focused tests feed
    /// an identical stream to one incremental and one reference instance.
    #if DEBUG
    func processAlertUsingReferenceEvaluator(
        _ alert: AlertSummary,
        evaluatedAt: Date
    ) -> [Campaign] {
        processAlert(alert, evaluatedAt: evaluatedAt, useReferenceEvaluator: true)
    }
    #endif

    private func processAlert(
        _ alert: AlertSummary,
        evaluatedAt: Date,
        useReferenceEvaluator: Bool
    ) -> [Campaign] {
        let id = nextAlertID
        nextAlertID &+= 1
        acceptedAlerts &+= 1

        let normalizedTactics = Set(alert.tactics.map(normalizeTactic))
        var aiCategories = Set<String>()
        if let category = aiGuardCategory(from: alert.ruleId) {
            aiCategories.insert(category)
            if isCompoundPromptInjection(alert) {
                aiCategories.insert("prompt-injection-compound")
            }
        }
        let indexed = IndexedAlert(
            id: id,
            summary: alert,
            normalizedTactics: normalizedTactics,
            aiCategories: aiCategories,
            contributesTactics: isTacticContributor(alert)
        )
        insertActiveAlert(indexed)
        recordForStormDetection(indexed)
        evictExcessAlerts()
        purgeStaleAlerts(evaluatedAt: evaluatedAt)
        peakActiveAlerts = max(peakActiveAlerts, alertsByID.count)

        let plans: [CandidatePlan]
        #if DEBUG
        plans = useReferenceEvaluator
            ? referenceCandidatePlans(latestAlert: alert, evaluatedAt: evaluatedAt)
            : incrementalCandidatePlans(latestAlert: alert, latestID: id, evaluatedAt: evaluatedAt)
        #else
        plans = incrementalCandidatePlans(latestAlert: alert, latestID: id, evaluatedAt: evaluatedAt)
        #endif

        var novel: [Campaign] = []
        novel.reserveCapacity(plans.count)
        for plan in plans where !isDuplicate(plan) {
            let campaign = materialize(plan)
            markEmitted(plan)
            detectedCampaigns.append(campaign)
            campaignsMaterialized &+= 1
            novel.append(campaign)
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
        let now = Date()
        purgeStaleAlerts(evaluatedAt: now)
        purgeStaleStormCounts(evaluatedAt: now)
        purgeStaleCampaigns(evaluatedAt: now)
        purgeStaleDedup(evaluatedAt: now)
    }

    public func telemetrySnapshot() -> TelemetrySnapshot {
        let accounted = UInt64(alertsByID.count) &+ timeExpiredAlerts &+ capEvictedAlerts
        return TelemetrySnapshot(
            acceptedAlerts: acceptedAlerts,
            activeAlerts: alertsByID.count,
            peakActiveAlerts: peakActiveAlerts,
            maxRecentAlerts: maxRecentAlerts,
            timeExpiredAlerts: timeExpiredAlerts,
            capEvictedAlerts: capEvictedAlerts,
            indexMutationOperations: indexMutationOperations,
            decisionOperations: decisionOperations,
            candidateAlertVisits: candidateAlertVisits,
            totalAccountedOperations: indexMutationOperations
                &+ decisionOperations
                &+ candidateAlertVisits,
            campaignsMaterialized: campaignsMaterialized,
            expirationEntries: expiration.count,
            ruleKeys: ruleAlertIDs.count,
            pidKeys: pidGroups.count,
            pathKeys: pathGroups.count,
            userKeys: userAlertIDs.count,
            tacticKeys: normalizedTacticAlertIDs.count,
            aiCategoryKeys: aiCategoryAlertIDs.count,
            conservationHolds: acceptedAlerts == accounted
                && alertsByID.count == activeOrder.count
                && alertsByID.count == expiration.count
        )
    }

    // MARK: - Incremental Evaluation

    private func incrementalCandidatePlans(
        latestAlert: AlertSummary,
        latestID: UInt64,
        evaluatedAt: Date
    ) -> [CandidatePlan] {
        // Five constant-time detector eligibility checks per admitted alert.
        // Any per-membership work is charged separately by the index counters.
        decisionOperations &+= 5
        var plans: [CandidatePlan] = []
        plans.reserveCapacity(5)
        if let plan = incrementalAlertStorm(
            latestAlert: latestAlert,
            latestID: latestID,
            evaluatedAt: evaluatedAt
        ) {
            plans.append(plan)
        }
        if let plan = incrementalKillChain(evaluatedAt: evaluatedAt) {
            plans.append(plan)
        }
        if let plan = incrementalAICompromise(evaluatedAt: evaluatedAt) {
            plans.append(plan)
        }
        if let plan = incrementalCoordinatedAttack(latestAlert: latestAlert, evaluatedAt: evaluatedAt) {
            plans.append(plan)
        }
        if let plan = incrementalLateralMovement(evaluatedAt: evaluatedAt) {
            plans.append(plan)
        }
        return plans
    }

    private func incrementalAlertStorm(
        latestAlert: AlertSummary,
        latestID: UInt64,
        evaluatedAt: Date
    ) -> CandidatePlan? {
        let cutoff = latestAlert.timestamp.addingTimeInterval(-stormWindow)
        let count = stormRules[latestAlert.ruleId]?.count(after: cutoff) ?? 0
        guard count >= stormThreshold, severityRank(latestAlert.severity) >= severityRank(.medium) else {
            return nil
        }
        let volumeSeverity: Severity = count >= stormCriticalThreshold ? .critical : .high
        let severity = severityRank(volumeSeverity) <= severityRank(latestAlert.severity)
            ? volumeSeverity : latestAlert.severity
        let title = severity == .critical
            ? "Alert Storm: active attack in progress"
            : "Alert Storm: possible scan or brute force"
        // The historical dedup discriminator came from the first contributing
        // *active* alert, and therefore fell back to "unknown" when the storm
        // counter survived campaign-window/cap eviction. The just-appended ID
        // proves the normal case in O(1); only a deliberately stale/out-of-order
        // latest alert needs a bounded per-rule fallback walk.
        let activeRuleIDs = ruleAlertIDs[latestAlert.ruleId]
        let hasActiveContributor: Bool
        if activeRuleIDs?.contains(latestID) == true {
            hasActiveContributor = true
        } else {
            var found = false
            for id in activeRuleIDs?.orderedIDs() ?? [] {
                decisionOperations &+= 1
                if let summary = alertsByID[id]?.summary, summary.timestamp > cutoff {
                    found = true
                    break
                }
            }
            hasActiveContributor = found
        }
        let dedupRuleID = hasActiveContributor ? latestAlert.ruleId : "unknown"
        let dedupKey = "\(CampaignType.alertStorm.rawValue):\(dedupRuleID)"
        guard !isDuplicate(dedupKey: dedupKey, severity: severity, detectedAt: evaluatedAt) else {
            return nil
        }
        let ratePerMinute = Double(count) / (stormWindow / 60.0)
        let description = "Rule \"\(latestAlert.ruleTitle)\" (\(latestAlert.ruleId)) fired \(count) times in \(Int(stormWindow))s (~\(String(format: "%.1f", ratePerMinute))/min)"
        return CandidatePlan(
            type: .alertStorm,
            severity: severity,
            title: title,
            description: description,
            selection: .ruleSince(latestAlert.ruleId, cutoff),
            tactics: nil,
            detectedAt: evaluatedAt,
            dedupKey: dedupKey
        )
    }

    private func incrementalKillChain(evaluatedAt: Date) -> CandidatePlan? {
        guard tacticContributorIDs.count >= 2 || tacticContributorCriticalCount > 0 else { return nil }
        let tacticCount = contributorTacticAlertIDs.count
        guard tacticCount >= 2 else { return nil }

        for (combo, result) in Self.twoTacticCombinations {
            decisionOperations &+= UInt64(combo.count)
            guard combo.allSatisfy({ contributorTacticAlertIDs[$0]?.isEmpty == false }) else {
                continue
            }
            let dedupKey = CampaignType.killChain.rawValue
            guard !isDuplicate(
                dedupKey: dedupKey,
                severity: result.severity,
                detectedAt: evaluatedAt
            ) else { return nil }
            let allTactics = Set(contributorTacticAlertIDs.keys)
            decisionOperations &+= UInt64(allTactics.count)
            let description = "Detected tactics: \(allTactics.sorted().joined(separator: ", ")) across \(tacticContributorIDs.count) alerts within \(Int(campaignWindow))s"
            return CandidatePlan(
                type: .killChain,
                severity: result.severity,
                title: result.title,
                description: description,
                selection: .tacticContributors,
                tactics: allTactics,
                detectedAt: evaluatedAt,
                dedupKey: dedupKey
            )
        }

        guard tacticCount >= minTacticsForKillChain else { return nil }
        let title: String
        let severity: Severity
        if contributorTacticAlertIDs["credential_access"]?.isEmpty == false
            && contributorTacticAlertIDs["persistence"]?.isEmpty == false
            && contributorTacticAlertIDs["command_and_control"]?.isEmpty == false {
            title = "Full Kill Chain"
            severity = .critical
        } else if contributorTacticAlertIDs["initial_access"]?.isEmpty == false
                    && contributorTacticAlertIDs["execution"]?.isEmpty == false
                    && contributorTacticAlertIDs["persistence"]?.isEmpty == false {
            title = "Malware Installation Chain"
            severity = .high
        } else {
            title = "Multi-Stage Attack"
            severity = .high
        }
        let dedupKey = CampaignType.killChain.rawValue
        guard !isDuplicate(dedupKey: dedupKey, severity: severity, detectedAt: evaluatedAt) else {
            return nil
        }
        let allTactics = Set(contributorTacticAlertIDs.keys)
        decisionOperations &+= UInt64(allTactics.count)
        let description = "Detected \(tacticCount) tactics: \(allTactics.sorted().joined(separator: ", ")) across \(tacticContributorIDs.count) alerts within \(Int(campaignWindow))s"
        return CandidatePlan(
            type: .killChain,
            severity: severity,
            title: title,
            description: description,
            selection: .tacticContributors,
            tactics: allTactics,
            detectedAt: evaluatedAt,
            dedupKey: dedupKey
        )
    }

    private func incrementalAICompromise(evaluatedAt: Date) -> CandidatePlan? {
        guard aiAlertIDs.count >= 2 else { return nil }
        let categoryCount = aiCategoryAlertIDs.count
        guard categoryCount >= 2 else { return nil }

        for (combo, title) in Self.aiTwoCategoryCombos {
            decisionOperations &+= UInt64(combo.count)
            guard combo.allSatisfy({ aiCategoryAlertIDs[$0]?.isEmpty == false }) else {
                continue
            }
            let dedupKey = CampaignType.aiCompromise.rawValue
            guard !isDuplicate(dedupKey: dedupKey, severity: .critical, detectedAt: evaluatedAt) else {
                return nil
            }
            let categories = Set(aiCategoryAlertIDs.keys)
            decisionOperations &+= UInt64(categories.count)
            let description = "AI Guard categories: \(categories.sorted().joined(separator: ", ")) across \(aiAlertIDs.count) alerts"
            return CandidatePlan(
                type: .aiCompromise,
                severity: .critical,
                title: title,
                description: description,
                selection: .aiAlerts,
                tactics: nil,
                detectedAt: evaluatedAt,
                dedupKey: dedupKey
            )
        }
        guard categoryCount >= 3 else { return nil }
        let dedupKey = CampaignType.aiCompromise.rawValue
        guard !isDuplicate(dedupKey: dedupKey, severity: .critical, detectedAt: evaluatedAt) else {
            return nil
        }
        let categories = Set(aiCategoryAlertIDs.keys)
        decisionOperations &+= UInt64(categories.count)
        let description = "AI Guard categories: \(categories.sorted().joined(separator: ", ")) across \(aiAlertIDs.count) alerts within \(Int(campaignWindow))s"
        return CandidatePlan(
            type: .aiCompromise,
            severity: .critical,
            title: "AI Tool Under Attack",
            description: description,
            selection: .aiAlerts,
            tactics: nil,
            detectedAt: evaluatedAt,
            dedupKey: dedupKey
        )
    }

    private func incrementalCoordinatedAttack(
        latestAlert: AlertSummary,
        evaluatedAt: Date
    ) -> CandidatePlan? {
        if Self.isKnownBenignProcess(processPath: latestAlert.processPath) { return nil }
        if let path = latestAlert.processPath, NoiseFilter.isTrustedBrowserHelper(path: path) { return nil }

        let keychainSingleEventRuleIds: Set<String> = [
            "d1a2b3c4-0448-4000-a000-000000000448",
            "d1a2b3c4-0501-4000-a000-000000000501",
        ]
        func plan(
            group: CoordinatedGroupIndex,
            selection: CandidateSelection,
            description: (Set<String>) -> String
        ) -> CandidatePlan? {
            guard group.ruleCounts.count >= 2 else { return nil }
            let isAIKeychainBreadcrumb = latestAlert.aiTool != nil
                && group.ruleCounts.count <= keychainSingleEventRuleIds.count
                && group.ruleCounts.keys.allSatisfy { keychainSingleEventRuleIds.contains($0) }
            if latestAlert.aiTool != nil && group.ruleCounts.count <= keychainSingleEventRuleIds.count {
                decisionOperations &+= UInt64(group.ruleCounts.count)
            }
            guard !isAIKeychainBreadcrumb else {
                return nil
            }
            let severity: Severity
            let title: String
            if group.tacticAlertIDs.count >= 3 {
                severity = .critical
                title = "Persistent Threat Actor"
            } else if group.tacticAlertIDs.count >= 2 {
                severity = .high
                title = "Coordinated Attack from single process"
            } else {
                return nil
            }
            let dedupKey = "\(CampaignType.coordinatedAttack.rawValue):\(group.processPathTarget)"
            let tactics = Set(group.tacticAlertIDs.keys)
            decisionOperations &+= UInt64(tactics.count)
            return CandidatePlan(
                type: .coordinatedAttack,
                severity: severity,
                title: title,
                description: description(tactics),
                selection: selection,
                tactics: tactics,
                detectedAt: evaluatedAt,
                dedupKey: dedupKey
            )
        }

        let pidPlan: CandidatePlan? = latestAlert.pid.flatMap { pid in
            guard let group = pidGroups[pid] else { return nil }
            return plan(group: group, selection: .pid(pid)) { tactics in
                "Process PID \(pid) triggered alerts spanning \(tactics.count) tactics: \(tactics.sorted().joined(separator: ", "))"
            }
        }
        let pathPlan: CandidatePlan? = latestAlert.processPath.flatMap { path in
            guard let group = pathGroups[path] else { return nil }
            return plan(group: group, selection: .path(path)) { tactics in
                let lastComponent = (path as NSString).lastPathComponent
                return "Process \(lastComponent) (\(path)) triggered alerts spanning \(tactics.count) tactics: \(tactics.sorted().joined(separator: ", "))"
            }
        }
        let selected: CandidatePlan?
        switch (pidPlan, pathPlan) {
        case let (.some(p), .some(q)): selected = p.severity >= q.severity ? p : q
        case let (.some(p), .none): selected = p
        case let (.none, .some(q)): selected = q
        case (.none, .none): selected = nil
        }
        guard let selected, !isDuplicate(selected) else { return nil }
        return selected
    }

    private func incrementalLateralMovement(evaluatedAt: Date) -> CandidatePlan? {
        guard userAlertIDs.count >= 2,
              normalizedTacticAlertIDs["lateral_movement"]?.isEmpty == false else {
            return nil
        }
        let dedupKey = CampaignType.lateralMovement.rawValue
        guard !isDuplicate(dedupKey: dedupKey, severity: .high, detectedAt: evaluatedAt) else {
            return nil
        }
        let users = Set(userAlertIDs.keys)
        decisionOperations &+= UInt64(users.count &+ rawTacticAlertIDs.count)
        let description = "Lateral-movement alert observed with activity across \(users.count) user contexts (\(users.sorted().joined(separator: ", "))) within \(Int(campaignWindow))s"
        return CandidatePlan(
            type: .lateralMovement,
            severity: .high,
            title: "Possible Lateral Movement",
            description: description,
            selection: .allAlerts,
            tactics: Set(rawTacticAlertIDs.keys),
            detectedAt: evaluatedAt,
            dedupKey: dedupKey
        )
    }

    private func materialize(_ plan: CandidatePlan) -> Campaign {
        let alerts = summaries(for: plan.selection)
        candidateAlertVisits &+= UInt64(alerts.count)
        return Campaign(
            id: makeCampaignId(),
            type: plan.type,
            severity: plan.severity,
            title: plan.title,
            description: plan.description,
            alerts: alerts,
            tactics: plan.tactics ?? aggregateTactics(alerts),
            timeSpanSeconds: timeSpan(of: alerts),
            detectedAt: plan.detectedAt
        )
    }

    private func summaries(for selection: CandidateSelection) -> [AlertSummary] {
        switch selection {
        case let .summaries(alerts):
            return alerts
        case let .ruleSince(ruleID, cutoff):
            return (ruleAlertIDs[ruleID]?.orderedIDs() ?? []).compactMap { id in
                guard let alert = alertsByID[id]?.summary, alert.timestamp > cutoff else { return nil }
                return alert
            }
        case .tacticContributors:
            return tacticContributorIDs.orderedIDs().compactMap { alertsByID[$0]?.summary }
        case .aiAlerts:
            return aiAlertIDs.orderedIDs().compactMap { alertsByID[$0]?.summary }
        case let .pid(pid):
            return (pidGroups[pid]?.alertIDs.orderedIDs() ?? []).compactMap { alertsByID[$0]?.summary }
        case let .path(path):
            return (pathGroups[path]?.alertIDs.orderedIDs() ?? []).compactMap { alertsByID[$0]?.summary }
        case .allAlerts:
            return activeOrder.orderedIDs().compactMap { alertsByID[$0]?.summary }
        }
    }

    private func severityRank(_ severity: Severity) -> Int {
        switch severity {
        case .critical: return 4
        case .high: return 3
        case .medium: return 2
        case .low: return 1
        case .informational: return 0
        }
    }

    // MARK: - Slow Reference Evaluation

    #if DEBUG
    private func referenceCandidatePlans(
        latestAlert: AlertSummary,
        evaluatedAt: Date
    ) -> [CandidatePlan] {
        var campaigns: [Campaign] = []
        if let value = checkAlertStorm(latestAlert: latestAlert) { campaigns.append(value) }
        if let value = checkKillChain() { campaigns.append(value) }
        if let value = checkAICompromise(evaluatedAt: evaluatedAt) { campaigns.append(value) }
        if let value = checkCoordinatedAttack(
            latestAlert: latestAlert,
            evaluatedAt: evaluatedAt
        ) { campaigns.append(value) }
        if let value = checkLateralMovement() { campaigns.append(value) }
        return campaigns.map { campaign in
            CandidatePlan(
                type: campaign.type,
                severity: campaign.severity,
                title: campaign.title,
                description: campaign.description,
                selection: .summaries(campaign.alerts),
                tactics: campaign.tactics,
                detectedAt: evaluatedAt,
                dedupKey: dedupKey(for: campaign)
            )
        }
    }
    #endif

    // MARK: - Storm Detection

    private func checkAlertStorm(latestAlert: AlertSummary) -> Campaign? {
        let ruleId = latestAlert.ruleId
        let cutoff = latestAlert.timestamp.addingTimeInterval(-stormWindow)
        guard let timestamps = stormRules[ruleId]?.timestamps else { return nil }
        let count = timestamps.filter { $0 > cutoff }.count

        guard count >= stormThreshold else { return nil }

        // FP fix: previously the storm severity came from VOLUME ALONE, so a
        // chatty low/info rule firing past the threshold minted a false
        // CRITICAL campaign (the #1 real-world false critical). Now: (1) gate —
        // only rules of severity >= .medium can form a storm (chatty low/info
        // rules are exactly the noise source), and (2) cap — the storm's
        // severity never exceeds the contributing rule's own severity.
        func rank(_ s: Severity) -> Int {
            switch s {
            case .critical: return 4; case .high: return 3; case .medium: return 2
            case .low: return 1; case .informational: return 0
            }
        }
        let ruleSeverity = latestAlert.severity
        guard rank(ruleSeverity) >= rank(.medium) else { return nil }
        let volumeSeverity: Severity = (count >= stormCriticalThreshold) ? .critical : .high
        let severity: Severity = rank(volumeSeverity) <= rank(ruleSeverity) ? volumeSeverity : ruleSeverity
        let isCritical = severity == .critical
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
    /// v1.17.1: 2 tactics is weak corroboration — credential_access + C2 is
    /// also the shape of a benign AI agent reading a .env then making a network
    /// call — so these are HIGH, not CRITICAL. CRITICAL is reserved for the
    /// 3-tactic credential+persistence+C2 chain (see checkKillChain).
    private static let twoTacticCombinations: [Set<String>: (title: String, severity: Severity)] = [
        Set(["initial_access", "persistence"]):
            ("Malware Installation Chain", .high),
        Set(["credential_access", "command_and_control"]):
            ("Partial Kill Chain (credential-access → C2)", .high),
        Set(["persistence", "command_and_control"]):
            ("Partial Kill Chain (persistence → C2)", .high),
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

    /// True when `processPath` is an Apple-signed system daemon under
    /// `/usr/libexec/` or `/System/Library/`. These processes (xpcproxy,
    /// mobileassetd, usernoted, rtcreportingd, nsurlsessiond, …)
    /// legitimately span MITRE tactics as part of macOS bookkeeping —
    /// `defense_evasion` from code-signing helpers, `initial_access` from
    /// XPC connection setup, etc. Counting them toward kill-chain tactic
    /// thresholds produced 15+ coordinated_attack campaigns on the
    /// v1.4.1 user's workstation in 24h, none of which were real.
    static func isAppleSystemDaemon(processPath: String?) -> Bool {
        guard let path = processPath else { return false }
        return path.hasPrefix("/usr/libexec/")
            || path.hasPrefix("/System/Library/")
            || path.hasPrefix("/System/Applications/Utilities/")
    }

    /// Strict auto-updater allow-list. Narrower than
    /// `isKnownBenignProcess` — does NOT include Apple system daemon
    /// paths (those would sweep in Terminal, Finder, Safari, any
    /// /System/Applications/Utilities/ tool). Use this helper when you
    /// want the engine to drop non-critical matches based on subject-
    /// or-ancestor path, because matching Terminal or Safari as
    /// ancestor would silently disable detection for all Terminal-
    /// launched activity.
    ///
    /// Empirically-driven: every entry corresponds to a specific field
    /// FP. Sparkle's `Autoupdate` binary lives at a deep path under
    /// `~/Library/Caches/<bundle-id>/org.sparkle-project.Sparkle/
    /// Installation/**/Autoupdate` — matching the `/Sparkle/`
    /// substring is safer than the full path variant with per-run
    /// nonces.
    static func isAutoUpdater(processPath: String?) -> Bool {
        guard let path = processPath else { return false }

        // Sparkle auto-update framework — bundled into many third-party
        // Mac apps (including MacCrab itself). The Autoupdate binary
        // does signing checks, file writes, and plist modifications as
        // part of an update; every one of those is a legitimate tactic.
        if path.contains("/Sparkle.framework/") { return true }
        if path.contains(".sparkle-project.Sparkle/Installation/") { return true }
        if path.hasSuffix("/Autoupdate") && path.contains("/Sparkle") { return true }

        // Google's auto-updater (GoogleUpdater, ex-Keystone). Ships with
        // Chrome, Drive, and various Google apps. Checks MDM state,
        // watches install receipts, writes to its own cache.
        if path.contains("/GoogleUpdater/") { return true }
        if path.contains("/GoogleSoftwareUpdate/") { return true }
        if path.contains("/Library/Caches/com.google.Keystone/") { return true }

        // Microsoft auto-update
        if path.contains("Microsoft AutoUpdate") { return true }

        // macOS native software-update stack
        if path.hasSuffix("/softwareupdated") { return true }
        if path.contains("SoftwareUpdateNotificationManager") { return true }

        // Homebrew — `brew upgrade` legitimately touches many tactics.
        if path.hasPrefix("/opt/homebrew/bin/brew") { return true }
        if path.hasPrefix("/usr/local/bin/brew") { return true }
        if path.contains("/Homebrew/Library/Homebrew/") { return true }

        return false
    }

    /// Broader allow-list for processes that legitimately span multiple
    /// tactics during normal operation: Apple system daemons plus known-
    /// benign auto-update, package-manager, and MDM binaries. Used by
    /// the kill-chain tactic counter and the coordinated-attack per-
    /// process filter where "is this process an OS component or an
    /// updater?" is the right question. DO NOT use this helper in
    /// ancestor-walk filters — Terminal.app would sweep in every admin
    /// invocation. See `isAutoUpdater` for the narrower check.
    static func isKnownBenignProcess(processPath: String?) -> Bool {
        guard let path = processPath else { return false }
        if isAppleSystemDaemon(processPath: path) { return true }
        return isAutoUpdater(processPath: path)
    }

    /// v1.19.1 (HN-audit): developer-tooling / package-manager runtime paths
    /// whose binaries routinely span multiple MITRE tactics on a clean dev box
    /// (node_modules CLIs — esbuild / workerd / wrangler — the Swift+Xcode
    /// toolchain incl. swiftpm-testing-helper, Homebrew Cellar, the Rust
    /// toolchain, and AI coding agents under ~/.local / ~/.claude). Distinct
    /// from `isKnownBenignProcess` (Apple daemons + updaters): these are
    /// user-space dev tools, but their multi-tactic base rate is high enough
    /// that letting their sub-CRITICAL alerts feed campaign correlation minted
    /// the audit's "esbuild is a 3-tactic C2 chain" / "workerd is a Persistent
    /// Threat Actor" FPs on the launch audience's own machines. CRITICAL alerts
    /// STILL feed — a genuine compromise of a dev tool (real credential theft,
    /// not a 404-package guess) must still escalate.
    public static func isDevelopmentToolingPath(_ processPath: String?) -> Bool {
        guard let path = processPath else { return false }
        let needles = [
            "/node_modules/", "/.npm/", "/.pnpm/", "/.yarn/", "/.nvm/",
            "/Xcode.app/", "/Library/Developer/", "swiftpm-testing-helper",
            "/.build/", "/DerivedData/",
            "/Cellar/", "/opt/homebrew/",
            "/.cargo/", "/.rustup/",
            "/.local/share/claude", "/.claude/",
            "/.vscode/", "/.cursor/",
        ]
        return needles.contains { path.contains($0) }
    }

    /// True when a dev-tooling alert is below CRITICAL and so must not feed
    /// campaign tactic-counting (see `isDevelopmentToolingPath`).
    private func isSubCriticalDevTooling(_ alert: AlertSummary) -> Bool {
        alert.severity < .critical && Self.isDevelopmentToolingPath(alert.processPath)
    }

    /// v1.19 (S1-T4): true when an alert must NOT contribute a tactic toward a
    /// kill-chain / coordinated-attack campaign because its subject is trusted
    /// (notarized Developer-ID / first-party / Apple platform binary) OR the
    /// activity is attributed to an AI agent, AND the alert is only LOW/MEDIUM.
    /// HIGH/CRITICAL trusted/agent alerts STILL count — slow-burn abuse of
    /// trusted-signed or agent tooling is exactly what campaign correlation is
    /// for. This stops the FP kill-chains the audit found minting on
    /// swiftpm-testing-helper / Xcode helpers / agent lineage ~every 2h.
    private func isLowSignalTrustedOrAgent(_ alert: AlertSummary) -> Bool {
        (alert.isTrustedSubject || alert.aiTool != nil) && alert.severity < .high
    }

    /// Shared contributor predicate for kill-chain and coordinated indexes.
    /// Keeping this single predicate prevents the two campaign paths from
    /// drifting back into the false-positive asymmetry fixed in v1.19.
    private func isTacticContributor(_ alert: AlertSummary) -> Bool {
        alert.severity >= .medium
            && !alert.ruleId.hasPrefix("maccrab.usb.")
            && !alert.ruleId.hasPrefix("maccrab.deep.crypto_token_extension")
            && !Self.isKnownBenignProcess(processPath: alert.processPath)
            && !isLowSignalTrustedOrAgent(alert)
            && !isSubCriticalDevTooling(alert)
    }

    private func checkKillChain() -> Campaign? {
        // v1.4: only count tactics contributed by medium+ severity alerts.
        // Low-severity discovery rules (ps, lsof, dscl, ioreg, …) produce
        // tactics ~every minute on a developer workstation; letting those
        // count for kill-chain detection meant every user who ran three
        // admin commands within 10 min got flagged as "Multi-Stage Attack".
        //
        // v1.4.2 tightening: also skip tactics contributed by USB hot-
        // plug alerts and Crypto-Token-Kit XPC alerts. Plugging in a
        // YubiKey near an open terminal shouldn't be a kill chain —
        // that exact scenario drove user's CAMP-8842E942 ("5 tactics,
        // 14 alerts") in field data. And exclude alerts whose subject
        // process sits under /usr/libexec/ or /System/Library/ (Apple
        // system daemons legitimately span tactics as part of OS
        // bookkeeping).
        let tacticContributingAlerts = recentAlerts.filter {
            $0.severity >= .medium
            && !$0.ruleId.hasPrefix("maccrab.usb.")
            && !$0.ruleId.hasPrefix("maccrab.deep.crypto_token_extension")
            // v1.6.4: broadened daemon filter to isKnownBenignProcess —
            // covers Sparkle/GoogleUpdater/brew/softwareupdated alongside
            // Apple system daemons. Auto-updaters routinely touch
            // multiple tactics during a single update cycle.
            && !Self.isKnownBenignProcess(processPath: $0.processPath)
            // v1.19 (S1-T4): exclude LOW/MEDIUM trusted-subject / agent-lineage
            // alerts from tactic-counting (HIGH/CRITICAL still feed). Stops the
            // FP kill-chains on swiftpm-testing-helper / Xcode helpers / agents.
            && !isLowSignalTrustedOrAgent($0)
            // v1.19.1 (HN-audit): exclude sub-CRITICAL alerts from dev-tooling
            // paths (node_modules / Xcode / homebrew / AI agents) — their
            // multi-tactic base rate minted "esbuild is an APT" chains.
            && !isSubCriticalDevTooling($0)
        }
        // v1.19.1 (HN-audit): a kill chain is multi-STAGE — require at least two
        // distinct contributing alerts. A single alert that carries multiple
        // MITRE tactic tags is one event, not a chain; titling it a
        // "Malware Installation Chain" was the audit's "1 alert → APT" FP.
        // EXCEPTION (rc.9 review): a single CRITICAL multi-tactic alert (e.g. a
        // confirmed credential+persistence+C2 match) is severe enough to escalate
        // to a campaign on its own — it gets the campaign-tier LLM deep
        // investigation. A single SUB-critical multi-tag alert is still not a chain.
        let hasCriticalContributor = tacticContributingAlerts.contains { $0.severity == .critical }
        guard tacticContributingAlerts.count >= 2 || hasCriticalContributor else { return nil }
        let allTactics = Set(tacticContributingAlerts.flatMap(\.tactics).map(normalizeTactic))
        guard allTactics.count >= 2 else { return nil }

        // Check specific 2-tactic combos first.
        //
        // v1.21.4 (deep-audit corr-campaign-anomaly): attach the FILTERED
        // `tacticContributingAlerts`, not the full unfiltered `recentAlerts`.
        // The campaign's aggregate attribution (affectedUsers / affectedExecutables
        // / techniques / aiTools, computed in Campaign.init) and the auto-generated
        // rules are derived from `alerts`; feeding the whole window over-reported
        // the blast radius and polluted rule generation with benign/sub-threshold
        // alerts that never contributed a tactic to this chain.
        for (combo, result) in Self.twoTacticCombinations {
            if combo.isSubset(of: allTactics) {
                let description = "Detected tactics: \(allTactics.sorted().joined(separator: ", ")) across \(tacticContributingAlerts.count) alerts within \(Int(campaignWindow))s"
                return Campaign(
                    id: makeCampaignId(),
                    type: .killChain,
                    severity: result.severity,
                    title: result.title,
                    description: description,
                    alerts: tacticContributingAlerts,
                    tactics: allTactics,
                    timeSpanSeconds: timeSpan(of: tacticContributingAlerts),
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
                // The one campaign shape we're "absolutely sure" on: credential
                // theft + persistence + C2 together is a real intrusion.
                title = "Full Kill Chain"
                severity = .critical
            } else if hasInitialAccess && hasExecution && hasPersistence {
                title = "Malware Installation Chain"
                severity = .high
            } else {
                // v1.17.1: a generic N-tactic mix that isn't the specific
                // credential+persistence+C2 chain is corroboration, not
                // certainty — HIGH, not CRITICAL.
                title = "Multi-Stage Attack"
                severity = .high
            }

            let description = "Detected \(allTactics.count) tactics: \(allTactics.sorted().joined(separator: ", ")) across \(tacticContributingAlerts.count) alerts within \(Int(campaignWindow))s"
            return Campaign(
                id: makeCampaignId(),
                type: .killChain,
                severity: severity,
                title: title,
                description: description,
                alerts: tacticContributingAlerts,
                tactics: allTactics,
                timeSpanSeconds: timeSpan(of: tacticContributingAlerts),
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

    private func checkAICompromise(evaluatedAt: Date) -> Campaign? {
        let cutoff = evaluatedAt.addingTimeInterval(-campaignWindow)
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

    private func checkCoordinatedAttack(
        latestAlert: AlertSummary,
        evaluatedAt: Date
    ) -> Campaign? {
        // v1.4.2: Apple system daemons (xpcproxy, mobileassetd, usernoted,
        // rtcreportingd, nsurlsessiond, …) span tactics by design as part of
        // macOS bookkeeping. Don't emit a coordinated-attack campaign for
        // them — 15+ FPs in user's 24h field window.
        // v1.6.4: broadened to isKnownBenignProcess which also covers Sparkle's
        // Autoupdate, GoogleUpdater, softwareupdated, brew, and MDM agents.
        if Self.isKnownBenignProcess(processPath: latestAlert.processPath) {
            return nil
        }
        // v1.4.9: trusted browser helpers (Google Chrome Helper, Safari
        // Web Content, Firefox Content, Edge Helper, Arc Helper, Electron
        // app helpers) legitimately span credential_access + exfiltration
        // tactics during normal sync to Google / Microsoft / Mozilla
        // clouds — reading their own Cookies / Login Data DBs and
        // uploading to the vendor backend. NoiseFilter Gate 3 suppresses
        // the individual rule matches; this mirrors that suppression at
        // the campaign layer so aggregated tactic-counting doesn't
        // resurrect the same FP class one tier up.
        if let path = latestAlert.processPath,
           NoiseFilter.isTrustedBrowserHelper(path: path) {
            return nil
        }

        let cutoff = evaluatedAt.addingTimeInterval(-campaignWindow)
        // v1.19 (S1-T4): exclude LOW/MEDIUM trusted-subject / agent-lineage
        // alerts from coordinated-attack tactic-counting — the same FP class the
        // kill-chain path now filters (swiftpm-testing-helper / Xcode helpers /
        // agents touching 2-3 tactics ~every 2h). HIGH/CRITICAL trusted/agent
        // alerts STILL feed. Applied to the grouped sets so BOTH the PID and
        // process-path branches count only genuine multi-step signal.
        // v1.19.0 (rc.3 live-test finding): the coordinated-attack tactic
        // counter must apply the SAME contributing-alert filter as
        // checkKillChain (above) — a severity floor + the benign-process /
        // usb / crypto-token excludes. Pre-this it had NONE (the comment below
        // admits it), so a benign dev runtime (workerd / wrangler) minted a
        // CRITICAL "Persistent Threat Actor" from a LOW "node_modules exec" +
        // a MEDIUM "curl|exec" alert spanning 3 tactics on one PID
        // (CAMP-995FA329). With the >= .medium floor the LOW alert drops out,
        // leaving one distinct rule, which the `distinctRuleIds.count >= 2`
        // gate below already rejects. Genuine multi-rule medium+ attacks on a
        // single PID still mint the campaign (must-fire preserved).
        let windowAlerts = recentAlerts.filter {
            $0.timestamp > cutoff
            && $0.severity >= .medium
            && !$0.ruleId.hasPrefix("maccrab.usb.")
            && !$0.ruleId.hasPrefix("maccrab.deep.crypto_token_extension")
            && !Self.isKnownBenignProcess(processPath: $0.processPath)
            && !isLowSignalTrustedOrAgent($0)
            // v1.19.1 (HN-audit): same dev-tooling carve-out as checkKillChain —
            // sub-CRITICAL alerts from node_modules / Xcode / homebrew / AI agents
            // minted CRITICAL "Persistent Threat Actor" campaigns (workerd,
            // swiftpm-testing-helper, Claude Code). CRITICAL still feeds.
            && !isSubCriticalDevTooling($0)
        }

        // v1.17.4 / CAMP-1: an AI coding tool legitimately querying the
        // keychain (`security find-generic-password`) is a breadcrumb, not a
        // campaign. When every contributing rule is one of these low-severity
        // single-event keychain/sudo approximations AND the activity is
        // attributed to an AI tool, do not mint a coordinated_attack — the
        // kill-chain path has a severity floor, these aggregation paths had
        // none. Applied to BOTH the PID and process-path branches so the FP
        // can't resurrect via whichever branch aggregates. The individual low
        // alerts still stand.
        let keychainSingleEventRuleIds: Set<String> = [
            "d1a2b3c4-0448-4000-a000-000000000448",  // auth_brute_force
            "d1a2b3c4-0501-4000-a000-000000000501",  // wifi_password_extraction
        ]
        func isAIKeychainBreadcrumb(_ ruleIds: Set<String>) -> Bool {
            return latestAlert.aiTool != nil && ruleIds.isSubset(of: keychainSingleEventRuleIds)
        }

        // v1.21.4 (deep-audit corr-campaign-anomaly): evaluate BOTH the per-PID
        // and per-executable groupings, then return the higher-severity campaign.
        //
        // The old code `return nil`-ed out of the whole function from inside the
        // PID branch whenever that PID had < 2 distinct rules (or was an AI
        // keychain breadcrumb), which made the process-path branch below dead
        // code: an attacker respawning one executable under several short-lived
        // PIDs — each PID firing exactly one distinct rule (PID1: discovery,
        // PID2: persistence, PID3: C2) — never minted a coordinated_attack even
        // though the shared binary spanned 3 tactics. Computing each candidate
        // independently lets the path branch aggregate across PIDs while the
        // per-branch FP guards (≥2 distinct rules, AI-keychain, ≥2 tactics) still
        // apply to each grouping.

        // Group by PID — alerts from the same process spanning multiple tactics.
        // The ≥2-distinct-ruleIds gate keeps a single alert that happens to carry
        // both `attack.discovery` AND `attack.defense_evasion` tags (the classic
        // csrutil-status pattern) from inflating the tactic count.
        let pidCampaign: Campaign? = latestAlert.pid.flatMap { pid in
            let pidAlerts = windowAlerts.filter { $0.pid == pid }
            let distinctRuleIds = Set(pidAlerts.map(\.ruleId))
            guard distinctRuleIds.count >= 2, !isAIKeychainBreadcrumb(distinctRuleIds) else { return nil }
            let pidTactics = aggregateNormalizedTactics(pidAlerts)
            let desc = "Process PID \(pid) triggered alerts spanning \(pidTactics.count) tactics: \(pidTactics.sorted().joined(separator: ", "))"
            return coordinatedCampaign(tactics: pidTactics, alerts: pidAlerts, description: desc)
        }

        // Group by process path — alerts from the same executable spanning
        // multiple tactics, aggregated across every PID that ran that binary.
        let pathCampaign: Campaign? = latestAlert.processPath.flatMap { path in
            let pathAlerts = windowAlerts.filter { $0.processPath == path }
            let distinctRuleIds = Set(pathAlerts.map(\.ruleId))
            guard distinctRuleIds.count >= 2, !isAIKeychainBreadcrumb(distinctRuleIds) else { return nil }
            let pathTactics = aggregateNormalizedTactics(pathAlerts)
            let lastComponent = (path as NSString).lastPathComponent
            let desc = "Process \(lastComponent) (\(path)) triggered alerts spanning \(pathTactics.count) tactics: \(pathTactics.sorted().joined(separator: ", "))"
            return coordinatedCampaign(tactics: pathTactics, alerts: pathAlerts, description: desc)
        }

        switch (pidCampaign, pathCampaign) {
        case let (.some(p), .some(q)): return p.severity >= q.severity ? p : q
        case let (.some(p), .none):    return p
        case let (.none, .some(q)):    return q
        case (.none, .none):           return nil
        }
    }

    /// Build a coordinated_attack campaign from a grouped alert set given its
    /// normalized tactics. Returns nil when the group spans fewer than 2 tactics.
    /// ≥3 tactics ⇒ CRITICAL "Persistent Threat Actor"; exactly 2 ⇒ HIGH
    /// "Coordinated Attack from single process".
    private func coordinatedCampaign(
        tactics: Set<String>,
        alerts: [AlertSummary],
        description: String
    ) -> Campaign? {
        let severity: Severity
        let title: String
        if tactics.count >= 3 {
            severity = .critical
            title = "Persistent Threat Actor"
        } else if tactics.count >= 2 {
            severity = .high
            title = "Coordinated Attack from single process"
        } else {
            return nil
        }
        return Campaign(
            id: makeCampaignId(),
            type: .coordinatedAttack,
            severity: severity,
            title: title,
            description: description,
            alerts: alerts,
            tactics: tactics,
            timeSpanSeconds: timeSpan(of: alerts),
            detectedAt: Date()
        )
    }

    // MARK: - Lateral Movement Detection

    private func checkLateralMovement() -> Campaign? {
        let alerts = recentAlerts
        let userIds = Set(alerts.compactMap(\.userId))
        guard userIds.count >= 2 else { return nil }

        // Require at least one actual lateral-movement alert. Previously any
        // two user contexts (root daemon + interactive user) would fire this,
        // which produced a constant false "Possible Lateral Movement" on every
        // developer workstation. A real lateral-movement campaign has at
        // minimum one ssh / vnc / ard / remote-exec rule hit.
        //
        // Normalize before matching, exactly as checkKillChain / the
        // coordinated-attack path do. Alert tactics arrive Sigma-prefixed
        // (`attack.lateral_movement`), so the old raw `.contains("lateral_movement")`
        // never matched and this detector was dead code — it could not fire.
        let lateralAlerts = alerts.filter {
            $0.tactics.contains { normalizeTactic($0) == "lateral_movement" }
        }
        guard !lateralAlerts.isEmpty else { return nil }

        let description = "Lateral-movement alert observed with activity across \(userIds.count) user contexts (\(userIds.sorted().joined(separator: ", "))) within \(Int(campaignWindow))s"
        return Campaign(
            id: makeCampaignId(),
            type: .lateralMovement,
            severity: .high,
            title: "Possible Lateral Movement",
            description: description,
            alerts: alerts,
            tactics: aggregateTactics(alerts),
            timeSpanSeconds: timeSpan(of: alerts),
            detectedAt: Date()
        )
    }

    // MARK: - Deduplication

    /// Build a dedup key from campaign type (plus a discriminator for storms and
    /// coordinated attacks so distinct targets aren't collapsed into one key).
    private func dedupKey(for campaign: Campaign) -> String {
        switch campaign.type {
        case .alertStorm:
            // Dedup per-rule for storms.
            let ruleId = campaign.alerts.first?.ruleId ?? "unknown"
            return "\(campaign.type.rawValue):\(ruleId)"
        case .coordinatedAttack:
            // v1.21.4 (deep-audit corr-campaign-anomaly): dedup per-executable.
            // A type-only key meant a coordinated attack on /tmp/a suppressed a
            // simultaneous, unrelated one on /tmp/b for the whole dedup window.
            // affectedExecutables is the distinct process paths across the
            // contributing alerts (usually a single binary for this type).
            let target = campaign.affectedExecutables.sorted().joined(separator: ",")
            return "\(campaign.type.rawValue):\(target)"
        default:
            return campaign.type.rawValue
        }
    }

    private func isDuplicate(_ plan: CandidatePlan) -> Bool {
        isDuplicate(
            dedupKey: plan.dedupKey,
            severity: plan.severity,
            detectedAt: plan.detectedAt
        )
    }

    private func isDuplicate(
        dedupKey: String,
        severity: Severity,
        detectedAt: Date
    ) -> Bool {
        guard let last = emittedCampaigns[dedupKey] else { return false }
        let interval = detectedAt.timeIntervalSince(last.date)
        guard interval >= 0 && interval < campaignDedupWindow else { return false }
        return severity <= last.severity
    }

    private func markEmitted(_ plan: CandidatePlan) {
        emittedCampaigns[plan.dedupKey] = (plan.detectedAt, plan.severity)
    }

    // MARK: - Helpers

    /// Scan-based view retained solely for the slow reference evaluator.
    private var recentAlerts: [AlertSummary] {
        activeOrder.orderedIDs().compactMap { alertsByID[$0]?.summary }
    }

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

    @discardableResult
    private static func insertID<Key: Hashable>(
        _ id: UInt64,
        key: Key,
        into index: inout [Key: OrderedIDIndex]
    ) -> UInt64 {
        var ids = index[key] ?? OrderedIDIndex()
        let inserted = ids.insert(id)
        index[key] = ids
        return inserted ? 1 : 0
    }

    @discardableResult
    private static func removeID<Key: Hashable>(
        _ id: UInt64,
        key: Key,
        from index: inout [Key: OrderedIDIndex]
    ) -> UInt64 {
        guard var ids = index[key], ids.remove(id) else { return 0 }
        if ids.isEmpty { index.removeValue(forKey: key) } else { index[key] = ids }
        return 1
    }

    private func insertActiveAlert(_ indexed: IndexedAlert) {
        alertsByID[indexed.id] = indexed
        _ = activeOrder.insert(indexed.id)
        expiration.insert(id: indexed.id, date: indexed.summary.timestamp)
        indexMutationOperations &+= 3

        indexMutationOperations &+= Self.insertID(
            indexed.id, key: indexed.summary.ruleId, into: &ruleAlertIDs
        )
        if let userID = indexed.summary.userId {
            indexMutationOperations &+= Self.insertID(indexed.id, key: userID, into: &userAlertIDs)
        }
        for tactic in indexed.summary.tactics {
            indexMutationOperations &+= Self.insertID(indexed.id, key: tactic, into: &rawTacticAlertIDs)
        }
        for tactic in indexed.normalizedTactics {
            indexMutationOperations &+= Self.insertID(
                indexed.id, key: tactic, into: &normalizedTacticAlertIDs
            )
        }
        if indexed.summary.ruleId.hasPrefix(Self.aiGuardPrefix) {
            _ = aiAlertIDs.insert(indexed.id)
            indexMutationOperations &+= 1
            for category in indexed.aiCategories {
                indexMutationOperations &+= Self.insertID(
                    indexed.id, key: category, into: &aiCategoryAlertIDs
                )
            }
        }
        if indexed.contributesTactics {
            _ = tacticContributorIDs.insert(indexed.id)
            indexMutationOperations &+= 1
            if indexed.summary.severity == .critical { tacticContributorCriticalCount += 1 }
            for tactic in indexed.normalizedTactics {
                indexMutationOperations &+= Self.insertID(
                    indexed.id, key: tactic, into: &contributorTacticAlertIDs
                )
            }
            if let pid = indexed.summary.pid {
                var group = pidGroups[pid] ?? CoordinatedGroupIndex()
                indexMutationOperations &+= group.insert(
                    id: indexed.id,
                    ruleID: indexed.summary.ruleId,
                    processPath: indexed.summary.processPath,
                    tactics: indexed.normalizedTactics
                )
                pidGroups[pid] = group
            }
            if let path = indexed.summary.processPath {
                var group = pathGroups[path] ?? CoordinatedGroupIndex()
                indexMutationOperations &+= group.insert(
                    id: indexed.id,
                    ruleID: indexed.summary.ruleId,
                    processPath: indexed.summary.processPath,
                    tactics: indexed.normalizedTactics
                )
                pathGroups[path] = group
            }
        }
    }

    private func recordForStormDetection(_ indexed: IndexedAlert) {
        let (doubled, overflow) = stormCriticalThreshold.multipliedReportingOverflow(by: 2)
        let cap = overflow ? Int.max : max(0, doubled)
        var rule = stormRules[indexed.summary.ruleId] ?? StormRuleIndex()
        let evicted = rule.insert(
            id: indexed.id,
            timestamp: indexed.summary.timestamp,
            cap: cap
        )
        if rule.isEmpty {
            stormRules.removeValue(forKey: indexed.summary.ruleId)
        } else {
            stormRules[indexed.summary.ruleId] = rule
        }
        stormRuleByID[indexed.id] = indexed.summary.ruleId
        stormExpiration.insert(id: indexed.id, date: indexed.summary.timestamp)
        for evictedID in evicted {
            stormRuleByID.removeValue(forKey: evictedID)
            _ = stormExpiration.remove(id: evictedID)
        }
        if evicted.contains(indexed.id) {
            stormRuleByID.removeValue(forKey: indexed.id)
        }
    }

    private enum RemovalReason { case timeExpired, capEvicted }

    private func removeActiveAlert(
        id: UInt64,
        reason: RemovalReason,
        expirationAlreadyRemoved: Bool = false
    ) {
        guard let indexed = alertsByID.removeValue(forKey: id) else { return }
        _ = activeOrder.remove(id)
        if !expirationAlreadyRemoved { _ = expiration.remove(id: id) }
        indexMutationOperations &+= 3

        indexMutationOperations &+= Self.removeID(
            id, key: indexed.summary.ruleId, from: &ruleAlertIDs
        )
        if let userID = indexed.summary.userId {
            indexMutationOperations &+= Self.removeID(id, key: userID, from: &userAlertIDs)
        }
        for tactic in indexed.summary.tactics {
            indexMutationOperations &+= Self.removeID(id, key: tactic, from: &rawTacticAlertIDs)
        }
        for tactic in indexed.normalizedTactics {
            indexMutationOperations &+= Self.removeID(
                id, key: tactic, from: &normalizedTacticAlertIDs
            )
        }
        if indexed.summary.ruleId.hasPrefix(Self.aiGuardPrefix) {
            if aiAlertIDs.remove(id) { indexMutationOperations &+= 1 }
            for category in indexed.aiCategories {
                indexMutationOperations &+= Self.removeID(
                    id, key: category, from: &aiCategoryAlertIDs
                )
            }
        }
        if indexed.contributesTactics {
            if tacticContributorIDs.remove(id) { indexMutationOperations &+= 1 }
            if indexed.summary.severity == .critical { tacticContributorCriticalCount -= 1 }
            for tactic in indexed.normalizedTactics {
                indexMutationOperations &+= Self.removeID(
                    id, key: tactic, from: &contributorTacticAlertIDs
                )
            }
            if let pid = indexed.summary.pid, var group = pidGroups[pid] {
                indexMutationOperations &+= group.remove(
                    id: indexed.id,
                    ruleID: indexed.summary.ruleId,
                    processPath: indexed.summary.processPath,
                    tactics: indexed.normalizedTactics
                )
                if group.isEmpty { pidGroups.removeValue(forKey: pid) } else { pidGroups[pid] = group }
            }
            if let path = indexed.summary.processPath, var group = pathGroups[path] {
                indexMutationOperations &+= group.remove(
                    id: indexed.id,
                    ruleID: indexed.summary.ruleId,
                    processPath: indexed.summary.processPath,
                    tactics: indexed.normalizedTactics
                )
                if group.isEmpty { pathGroups.removeValue(forKey: path) } else { pathGroups[path] = group }
            }
        }
        switch reason {
        case .timeExpired: timeExpiredAlerts &+= 1
        case .capEvicted: capEvictedAlerts &+= 1
        }
    }

    // MARK: - Cleanup

    /// Evict exactly the oldest *inserted active* alerts before time expiry,
    /// preserving the historical cap-before-purge behavior for out-of-order
    /// timestamps.
    private func evictExcessAlerts() {
        var evicted = 0
        while alertsByID.count > maxRecentAlerts, let id = activeOrder.firstID() {
            removeActiveAlert(id: id, reason: .capEvicted)
            evicted += 1
        }
        // Sustained over-cap traffic used to emit one warning per alert, which
        // turned the safety cap itself into an I/O hot path. Telemetry retains
        // every eviction; logs report the first and each 1k boundary.
        if evicted > 0,
           capEvictedAlerts == UInt64(evicted) || capEvictedAlerts.isMultiple(of: 1_000) {
            logger.warning("CampaignDetector: evicted \(evicted) oldest alerts (cap=\(self.maxRecentAlerts))")
        }
    }

    private func purgeStaleAlerts(evaluatedAt: Date) {
        let cutoff = evaluatedAt.addingTimeInterval(-campaignWindow)
        while let expired = expiration.popIfExpired(cutoff: cutoff) {
            removeActiveAlert(
                id: expired.id,
                reason: .timeExpired,
                expirationAlreadyRemoved: true
            )
        }
    }

    private func purgeStaleStormCounts(evaluatedAt: Date) {
        let cutoff = evaluatedAt.addingTimeInterval(-stormWindow)
        while let expired = stormExpiration.popIfExpired(cutoff: cutoff) {
            guard let ruleID = stormRuleByID.removeValue(forKey: expired.id),
                  var rule = stormRules[ruleID] else { continue }
            _ = rule.remove(id: expired.id)
            if rule.isEmpty { stormRules.removeValue(forKey: ruleID) } else { stormRules[ruleID] = rule }
        }
    }

    private func purgeStaleCampaigns(evaluatedAt: Date) {
        let cutoff = evaluatedAt.addingTimeInterval(-86400) // Keep campaigns for 24 hours
        detectedCampaigns.removeAll { $0.detectedAt <= cutoff }
    }

    private func purgeStaleDedup(evaluatedAt: Date) {
        emittedCampaigns = emittedCampaigns.filter { _, value in
            evaluatedAt.timeIntervalSince(value.date) < campaignDedupWindow
        }
    }

    /// Adversarial test seam: independently checks every active alert's index
    /// membership plus the three-way admission conservation equation.
    func indexInvariantFailures() -> [String] {
        var failures: [String] = []
        let activeIDs = Set(alertsByID.keys)
        if activeOrder.memberIDs != activeIDs { failures.append("active-order membership drift") }
        if expiration.ids != activeIDs { failures.append("expiration membership drift") }
        let accounted = UInt64(alertsByID.count) &+ timeExpiredAlerts &+ capEvictedAlerts
        if accounted != acceptedAlerts { failures.append("admission conservation drift") }

        var expectedRules: [String: Set<UInt64>] = [:]
        var expectedUsers: [String: Set<UInt64>] = [:]
        var expectedRawTactics: [String: Set<UInt64>] = [:]
        var expectedNormalizedTactics: [String: Set<UInt64>] = [:]
        var expectedContributorTactics: [String: Set<UInt64>] = [:]
        var expectedAICategories: [String: Set<UInt64>] = [:]
        var expectedAI: Set<UInt64> = []
        var expectedContributors: Set<UInt64> = []
        var expectedPIDs: [Int: Set<UInt64>] = [:]
        var expectedPaths: [String: Set<UInt64>] = [:]
        var expectedCriticalContributors = 0
        for (id, indexed) in alertsByID {
            expectedRules[indexed.summary.ruleId, default: []].insert(id)
            if let user = indexed.summary.userId { expectedUsers[user, default: []].insert(id) }
            for tactic in indexed.summary.tactics { expectedRawTactics[tactic, default: []].insert(id) }
            for tactic in indexed.normalizedTactics {
                expectedNormalizedTactics[tactic, default: []].insert(id)
            }
            if indexed.summary.ruleId.hasPrefix(Self.aiGuardPrefix) {
                expectedAI.insert(id)
                for category in indexed.aiCategories {
                    expectedAICategories[category, default: []].insert(id)
                }
            }
            if indexed.contributesTactics {
                expectedContributors.insert(id)
                if indexed.summary.severity == .critical { expectedCriticalContributors += 1 }
                for tactic in indexed.normalizedTactics {
                    expectedContributorTactics[tactic, default: []].insert(id)
                }
                if let pid = indexed.summary.pid { expectedPIDs[pid, default: []].insert(id) }
                if let path = indexed.summary.processPath { expectedPaths[path, default: []].insert(id) }
            }
        }

        if ruleAlertIDs.mapValues(\.memberIDs) != expectedRules { failures.append("rule index drift") }
        if userAlertIDs.mapValues(\.memberIDs) != expectedUsers { failures.append("user index drift") }
        if rawTacticAlertIDs.mapValues(\.memberIDs) != expectedRawTactics {
            failures.append("raw tactic index drift")
        }
        if normalizedTacticAlertIDs.mapValues(\.memberIDs) != expectedNormalizedTactics {
            failures.append("normalized tactic index drift")
        }
        if contributorTacticAlertIDs.mapValues(\.memberIDs) != expectedContributorTactics {
            failures.append("contributor tactic index drift")
        }
        if aiCategoryAlertIDs.mapValues(\.memberIDs) != expectedAICategories {
            failures.append("AI category index drift")
        }
        if aiAlertIDs.memberIDs != expectedAI { failures.append("AI index drift") }
        if tacticContributorIDs.memberIDs != expectedContributors { failures.append("contributor index drift") }
        if pidGroups.mapValues({ $0.alertIDs.memberIDs }) != expectedPIDs { failures.append("PID index drift") }
        if pathGroups.mapValues({ $0.alertIDs.memberIDs }) != expectedPaths { failures.append("path index drift") }
        if tacticContributorCriticalCount != expectedCriticalContributors {
            failures.append("critical contributor count drift")
        }
        return failures
    }
}

// MARK: - Private bounded index primitives

/// Insertion-ordered ID membership with O(1)-amortized arbitrary removal.
/// Interior tombstones are compacted only after enough removals have accrued,
/// so cleanup work is chargeable to removed entries rather than every alert.
private struct OrderedIDIndex {
    private var storage: [UInt64] = []
    private var head = 0
    private var members: Set<UInt64> = []

    var count: Int { members.count }
    var isEmpty: Bool { members.isEmpty }
    var memberIDs: Set<UInt64> { members }

    func contains(_ id: UInt64) -> Bool { members.contains(id) }

    @discardableResult
    mutating func insert(_ id: UInt64) -> Bool {
        guard members.insert(id).inserted else { return false }
        storage.append(id)
        return true
    }

    @discardableResult
    mutating func remove(_ id: UInt64) -> Bool {
        guard members.remove(id) != nil else { return false }
        trimLeadingTombstones()
        compactIfNeeded()
        return true
    }

    mutating func firstID() -> UInt64? {
        trimLeadingTombstones()
        guard head < storage.count else { return nil }
        return storage[head]
    }

    func orderedIDs() -> [UInt64] {
        guard head < storage.count else { return [] }
        return storage[head...].filter { members.contains($0) }
    }

    private mutating func trimLeadingTombstones() {
        while head < storage.count && !members.contains(storage[head]) { head += 1 }
        if members.isEmpty {
            storage.removeAll(keepingCapacity: true)
            head = 0
        }
    }

    private mutating func compactIfNeeded() {
        guard !members.isEmpty else { return }
        let trailingCount = storage.count - head
        let tombstones = trailingCount - members.count
        let enoughHeadWaste = head >= 256 && head >= storage.count / 2
        let enoughInteriorWaste = tombstones >= 128 && tombstones >= members.count
        guard enoughHeadWaste || enoughInteriorWaste else { return }
        storage = storage[head...].filter { members.contains($0) }
        head = 0
    }
}

/// Exact timestamp expiry with arbitrary removal (needed when insertion-order
/// cap eviction removes an alert that has not reached its timestamp deadline).
private struct IndexedExpirationHeap {
    struct Node {
        let id: UInt64
        let date: Date
    }

    private var nodes: [Node] = []
    private var positions: [UInt64: Int] = [:]

    var count: Int { nodes.count }
    var ids: Set<UInt64> { Set(positions.keys) }

    mutating func insert(id: UInt64, date: Date) {
        if positions[id] != nil { _ = remove(id: id) }
        nodes.append(Node(id: id, date: date))
        positions[id] = nodes.count - 1
        siftUp(from: nodes.count - 1)
    }

    @discardableResult
    mutating func remove(id: UInt64) -> Bool {
        guard let index = positions.removeValue(forKey: id) else { return false }
        let last = nodes.removeLast()
        guard index < nodes.count else { return true }
        nodes[index] = last
        positions[last.id] = index
        if index > 0 && ordered(nodes[index], before: nodes[(index - 1) / 2]) {
            siftUp(from: index)
        } else {
            siftDown(from: index)
        }
        return true
    }

    mutating func popIfExpired(cutoff: Date) -> Node? {
        guard let first = nodes.first, first.date <= cutoff else { return nil }
        _ = remove(id: first.id)
        return first
    }

    private func ordered(_ lhs: Node, before rhs: Node) -> Bool {
        lhs.date == rhs.date ? lhs.id < rhs.id : lhs.date < rhs.date
    }

    private mutating func siftUp(from start: Int) {
        var child = start
        while child > 0 {
            let parent = (child - 1) / 2
            guard ordered(nodes[child], before: nodes[parent]) else { break }
            swap(child, parent)
            child = parent
        }
    }

    private mutating func siftDown(from start: Int) {
        var parent = start
        while true {
            let left = parent * 2 + 1
            guard left < nodes.count else { return }
            let right = left + 1
            let child = right < nodes.count && ordered(nodes[right], before: nodes[left])
                ? right : left
            guard ordered(nodes[child], before: nodes[parent]) else { return }
            swap(parent, child)
            parent = child
        }
    }

    private mutating func swap(_ lhs: Int, _ rhs: Int) {
        nodes.swapAt(lhs, rhs)
        positions[nodes[lhs].id] = lhs
        positions[nodes[rhs].id] = rhs
    }
}

private struct CoordinatedGroupIndex {
    var alertIDs = OrderedIDIndex()
    var ruleCounts: [String: Int] = [:]
    var tacticAlertIDs: [String: OrderedIDIndex] = [:]
    var processPathCounts: [String: Int] = [:]
    private(set) var processPathTarget = ""

    var isEmpty: Bool { alertIDs.isEmpty }

    mutating func insert(
        id: UInt64,
        ruleID: String,
        processPath: String?,
        tactics: Set<String>
    ) -> UInt64 {
        var operations: UInt64 = alertIDs.insert(id) ? 1 : 0
        ruleCounts[ruleID, default: 0] += 1
        operations &+= 1
        if let processPath {
            let introducedPath = processPathCounts[processPath] == nil
            processPathCounts[processPath, default: 0] += 1
            if introducedPath {
                refreshProcessPathTarget()
                operations &+= UInt64(processPathCounts.count)
            }
            operations &+= 1
        }
        for tactic in tactics {
            var ids = tacticAlertIDs[tactic] ?? OrderedIDIndex()
            if ids.insert(id) { operations &+= 1 }
            tacticAlertIDs[tactic] = ids
        }
        return operations
    }

    mutating func remove(
        id: UInt64,
        ruleID: String,
        processPath: String?,
        tactics: Set<String>
    ) -> UInt64 {
        var operations: UInt64 = alertIDs.remove(id) ? 1 : 0
        Self.decrement(ruleID, in: &ruleCounts)
        operations &+= 1
        if let processPath {
            let removedPath = processPathCounts[processPath] == 1
            Self.decrement(processPath, in: &processPathCounts)
            if removedPath {
                refreshProcessPathTarget()
                operations &+= UInt64(processPathCounts.count)
            }
            operations &+= 1
        }
        for tactic in tactics {
            guard var ids = tacticAlertIDs[tactic], ids.remove(id) else { continue }
            operations &+= 1
            if ids.isEmpty { tacticAlertIDs.removeValue(forKey: tactic) }
            else { tacticAlertIDs[tactic] = ids }
        }
        return operations
    }

    private static func decrement<Key: Hashable>(_ key: Key, in counts: inout [Key: Int]) {
        guard let count = counts[key] else { return }
        if count <= 1 { counts.removeValue(forKey: key) } else { counts[key] = count - 1 }
    }

    private mutating func refreshProcessPathTarget() {
        processPathTarget = processPathCounts.keys.sorted().joined(separator: ",")
    }
}

/// Bounded per-rule storm counter. Timestamps are sorted for O(log cap) count
/// queries; insertion/removal shifts are bounded by `2 * criticalThreshold`,
/// never by the 5k campaign window.
private struct StormRuleIndex {
    private var insertionOrder = OrderedIDIndex()
    private var timestampsByID: [UInt64: Date] = [:]
    private var sortedTimestamps: [Date] = []

    var isEmpty: Bool { timestampsByID.isEmpty }
    var timestamps: [Date] { sortedTimestamps }

    mutating func insert(id: UInt64, timestamp: Date, cap: Int) -> [UInt64] {
        _ = insertionOrder.insert(id)
        timestampsByID[id] = timestamp
        sortedTimestamps.insert(timestamp, at: upperBound(timestamp))
        var evicted: [UInt64] = []
        while timestampsByID.count > cap, let oldest = insertionOrder.firstID() {
            _ = remove(id: oldest)
            evicted.append(oldest)
        }
        return evicted
    }

    @discardableResult
    mutating func remove(id: UInt64) -> Bool {
        guard let timestamp = timestampsByID.removeValue(forKey: id) else { return false }
        _ = insertionOrder.remove(id)
        let index = lowerBound(timestamp)
        if index < sortedTimestamps.count && sortedTimestamps[index] == timestamp {
            sortedTimestamps.remove(at: index)
        }
        return true
    }

    func count(after cutoff: Date) -> Int {
        sortedTimestamps.count - upperBound(cutoff)
    }

    private func lowerBound(_ value: Date) -> Int {
        var low = 0
        var high = sortedTimestamps.count
        while low < high {
            let mid = low + (high - low) / 2
            if sortedTimestamps[mid] < value { low = mid + 1 } else { high = mid }
        }
        return low
    }

    private func upperBound(_ value: Date) -> Int {
        var low = 0
        var high = sortedTimestamps.count
        while low < high {
            let mid = low + (high - low) / 2
            if sortedTimestamps[mid] <= value { low = mid + 1 } else { high = mid }
        }
        return low
    }
}
