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

    /// Recently emitted campaigns keyed by dedup key → (detection time, the
    /// highest severity emitted for that key within the window). The severity is
    /// tracked so a genuine escalation (e.g. a HIGH coordinated attack becoming
    /// CRITICAL) can re-emit inside the dedup window instead of being swallowed.
    private var emittedCampaigns: [String: (date: Date, severity: Severity)] = [:]

    /// Detected campaigns (kept for `activeCampaigns` queries).
    private var detectedCampaigns: [Campaign] = []

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
        self.maxRecentAlerts = maxRecentAlerts
        // v1.12.0 dev-mode gate — wider dedup window (1200 s = 20 min)
        // when MACCRAB_DEV_MODE=1, so iterative test runs of similar
        // tactic patterns don't generate repeated campaign alerts.
        self.campaignDedupWindow = campaignDedupWindow ?? (devMode ? 1200 : 600)
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
        // v1.11.0 (audit stability MEDIUM): bound each rule's
        // timestamp array inline. Pre-fix `purgeStaleStormCounts()`
        // ran only at the 5-min sweep tick, so a high-volume rule
        // accumulated thousands of timestamps between sweeps + held
        // them in memory. Cap at 2× stormCriticalThreshold — well
        // above the largest legitimate window query yet bounded.
        let cap = stormCriticalThreshold * 2
        if let count = ruleAlertCounts[alert.ruleId]?.count, count > cap {
            ruleAlertCounts[alert.ruleId]?.removeFirst(count - cap)
        }
    }

    private func checkAlertStorm(latestAlert: AlertSummary) -> Campaign? {
        let ruleId = latestAlert.ruleId
        guard let timestamps = ruleAlertCounts[ruleId] else { return nil }

        let cutoff = latestAlert.timestamp.addingTimeInterval(-stormWindow)
        let recentTimestamps = timestamps.filter { $0 > cutoff }
        let count = recentTimestamps.count

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

        let cutoff = Date().addingTimeInterval(-campaignWindow)
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
        // Use the incremental user-ID index — O(1), not O(n).
        guard userIdCounts.count >= 2 else { return nil }

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
        let lateralAlerts = recentAlerts.filter {
            $0.tactics.contains { normalizeTactic($0) == "lateral_movement" }
        }
        guard !lateralAlerts.isEmpty else { return nil }

        let userIds = Set(userIdCounts.keys)
        let description = "Lateral-movement alert observed with activity across \(userIds.count) user contexts (\(userIds.sorted().joined(separator: ", "))) within \(Int(campaignWindow))s"
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

    private func isDuplicate(_ campaign: Campaign) -> Bool {
        let key = dedupKey(for: campaign)
        guard let last = emittedCampaigns[key] else { return false }
        let interval = campaign.detectedAt.timeIntervalSince(last.date)
        // Guard against clock going backward (NTP adjustment, DST): a negative
        // interval must not suppress the new campaign.
        guard interval >= 0 && interval < campaignDedupWindow else { return false }
        // v1.21.4 (deep-audit corr-campaign-anomaly): a strict severity
        // ESCALATION (e.g. HIGH → CRITICAL) is not a duplicate — the operator
        // needs to see that a campaign got worse even inside the dedup window.
        // A same-or-lower-severity repeat is still suppressed.
        return campaign.severity <= last.severity
    }

    private func markEmitted(_ campaign: Campaign) {
        let key = dedupKey(for: campaign)
        emittedCampaigns[key] = (campaign.detectedAt, campaign.severity)
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
        if let uid = alert.userId {
            userIdCounts[uid, default: 0] += 1
        }
    }

    /// Remove a stale alert from the tactic and user-ID indexes.
    private func removeFromIndexes(_ alert: AlertSummary) {
        if let uid = alert.userId {
            if let count = userIdCounts[uid] {
                let newCount = count - 1
                if newCount <= 0 {
                    userIdCounts.removeValue(forKey: uid)
                } else {
                    userIdCounts[uid] = newCount
                }
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
        emittedCampaigns = emittedCampaigns.filter { _, value in
            now.timeIntervalSince(value.date) < campaignDedupWindow
        }
    }
}
