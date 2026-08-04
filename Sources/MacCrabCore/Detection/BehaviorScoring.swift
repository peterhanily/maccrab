// BehaviorScoring.swift
// MacCrabCore
//
// Behavioral scoring engine: accumulates weighted suspicion indicators
// per process. When a process's score crosses a threshold, a high-confidence
// alert is generated — even if no single rule matched at critical severity.
//
// This catches sophisticated attacks that distribute their indicators across
// many small actions, each below the alert threshold individually.

import Foundation
import os.log

/// Per-process behavioral suspicion scoring.
///
/// Each event adds weighted indicators to the process's score. When the
/// score exceeds the configured threshold, a composite behavioral alert fires.
/// Scores decay over time to avoid permanent tainting of long-running processes.
public actor BehaviorScoring {

    private let logger = Logger(subsystem: "com.maccrab", category: "behavior-scoring")

    // MARK: - Configuration

    /// Score threshold to trigger a behavioral alert.
    private let alertThreshold: Double

    /// Score threshold for critical severity (well above alert).
    private let criticalThreshold: Double

    /// Time window for score decay (scores halve every this many seconds).
    private let decayHalfLife: TimeInterval

    /// Maximum tracked processes (LRU eviction).
    private let maxTrackedProcesses: Int

    // MARK: - State

    /// Per-process score tracking.
    private var processScores: [ProcessKey: ProcessScore] = [:]

    /// Order of insertion for LRU eviction.
    private var insertionOrder: [ProcessKey] = []

    /// Set of process keys that have already triggered alerts (avoid re-alerting).
    private var alerted: Set<ProcessKey> = []

    /// Threshold crossings remain pending until the alert sink has either
    /// committed the corresponding composite alert or deliberately filtered /
    /// collapsed it. Returning a result is not delivery: callers may fail while
    /// persisting, and spending the one-shot latch before that boundary silently
    /// disabled the detector on its most common non-rule indicator paths.
    private var pendingThresholds: [ProcessKey: ScoringResult] = [:]
    private var thresholdTokenToProcess: [UInt64: ProcessKey] = [:]
    private var nextThresholdToken: UInt64 = 0
    private var thresholdCrossingsTotal: UInt64 = 0
    private var thresholdCommittedTotal: UInt64 = 0
    private var thresholdSuppressedTotal: UInt64 = 0
    private var thresholdAbandonedTotal: UInt64 = 0
    private var thresholdDeliveryFailuresTotal: UInt64 = 0

    // MARK: - Types

    private struct ProcessKey: Hashable {
        let pid: Int32
        let path: String
    }

    private struct ProcessScore {
        var rawScore: Double = 0
        var lastUpdate: Date = Date()
        var indicators: [Indicator] = []
        /// Per-indicator-name last-add timestamp for cooldown suppression.
        /// Without this, a long-running AI/dev tool that triggers the same
        /// indicator (e.g. `ai_tool_unapproved_network`) on every HTTPS
        /// request can walk itself past the alert threshold trivially.
        var indicatorLastAdd: [String: Date] = [:]
    }

    /// Minimum time between counting the same indicator twice for the same
    /// process. Tuned short enough that a fresh attack still accumulates
    /// quickly (multiple distinct indicators), but long enough that a chatty
    /// benign process does not repeatedly stack the same indicator.
    private static let indicatorCooldown: TimeInterval = 120

    /// v1.12.0 dev-mode gate. Resolved once at type-init; flipping
    /// MACCRAB_DEV_MODE mid-run requires a daemon restart.
    ///
    /// v1.12.0 post-audit (M-Sec2): gated behind `#if DEBUG` so a
    /// release-build daemon ignores `MACCRAB_DEV_MODE` entirely. A
    /// root attacker dropping `/Library/LaunchDaemons/com.maccrab.plist`
    /// with `EnvironmentVariables.MACCRAB_DEV_MODE=1` cannot lower
    /// thresholds on a release build via env var alone — they'd need
    /// to swap the signed binary, which the System Extension activation
    /// flow refuses (sysextd checks Team ID + entitlements before load).
    private static let devMode: Bool = {
        #if DEBUG
        return Foundation.ProcessInfo.processInfo.environment["MACCRAB_DEV_MODE"] == "1"
        #else
        return false
        #endif
    }()

    /// A single behavioral indicator added to a process's score.
    public struct Indicator: Sendable {
        public let name: String
        public let weight: Double
        public let detail: String
        public let timestamp: Date

        public init(name: String, weight: Double, detail: String = "") {
            self.name = name
            self.weight = weight
            self.detail = detail
            self.timestamp = Date()
        }
    }

    /// Result of scoring an event.
    public struct ScoringResult: Sendable {
        /// Opaque acknowledgement token. A caller must resolve it only after
        /// the durable alert boundary reports committed or intentionally
        /// suppressed/collapsed. Storage failures leave it retryable.
        public let deliveryToken: UInt64
        public let processPath: String
        public let pid: Int32
        public let totalScore: Double
        public let indicators: [(name: String, weight: Double, detail: String)]
        public let severity: Severity
    }

    public enum ThresholdResolution: Sendable {
        case committed
        case filteredOrSuppressed
    }

    public struct ThresholdTelemetry: Sendable, Equatable {
        public let crossings: UInt64
        public let committed: UInt64
        public let filteredOrSuppressed: UInt64
        public let abandoned: UInt64
        public let pending: Int
        public let deliveryFailures: UInt64

        public var conservesCrossings: Bool {
            crossings == committed + filteredOrSuppressed + abandoned
                + UInt64(pending)
        }
    }

    // MARK: - Indicator Weights

    /// Standard indicator weights. Higher = more suspicious.
    public static let weights: [String: Double] = [
        // Process indicators
        "unsigned_binary":              3.0,
        // v1.19.1 (rc.9 review): a REDUCED-weight variant for legitimately-unsigned
        // developer tooling (node_modules CLIs, Homebrew, the Swift/Xcode toolchain,
        // AI agents). Benign dev tools shouldn't FP at 3.0, but a binary PLANTED on
        // a dev path still accrues compound score with its other indicators.
        "unsigned_dev_tooling":         1.0,
        "adhoc_signed":                 1.5,
        "executed_from_tmp":            4.0,
        "executed_from_downloads":      3.0,
        "shell_spawned_by_non_terminal": 3.0,
        "interpreter_with_eval":        2.5,
        "obfuscated_commandline":       3.0,
        "long_base64_in_args":          3.5,

        // File indicators
        "writes_launch_agent":          5.0,
        "writes_launch_daemon":         6.0,
        "writes_cron":                  4.0,
        "writes_shell_profile":         3.0,
        "modifies_binary":              3.0,
        "writes_hidden_file":           2.0,

        // Network indicators
        "connects_raw_ip":              2.0,
        "connects_unusual_port":        2.5,
        "connects_known_bad_ip":        8.0,
        "connects_tor":                 4.0,
        "high_entropy_dns":             3.0,

        // Credential/data access
        "reads_keychain":               4.0,
        "reads_ssh_keys":               3.5,
        "reads_browser_data":           3.0,
        "accesses_password_db":         4.0,

        // Defense evasion
        "deletes_logs":                 5.0,
        "disables_gatekeeper":          6.0,
        "removes_quarantine":           4.0,
        "kills_security_tool":          7.0,

        // TCC
        "camera_access_unsigned":       4.0,
        "microphone_access_unsigned":   4.0,
        "screen_recording_unsigned":    3.5,
        "full_disk_access_unsigned":    5.0,

        // AI Tool Monitoring
        "ai_tool_detected":             0.5,
        "ai_tool_spawns_shell":         2.0,
        "ai_tool_runs_sudo":            6.0,
        "ai_tool_credential_access":    8.0,
        "ai_tool_boundary_violation":   5.0,
        "ai_tool_installs_unknown_pkg": 4.0,
        "ai_tool_persistence_write":    7.0,
        "ai_tool_downloads_and_exec":   6.0,
        "prompt_injection_low":         2.0,
        "prompt_injection_medium":      4.0,
        "prompt_injection_high":        7.0,
        "prompt_injection_critical":    9.0,
        "prompt_injection_compound":   10.0,

        // Topology anomalies (shape-based process-tree detection)
        "launchd_spawned_shell":                8.0,
        "system_process_spawning_staged_binary": 7.0,
        "anomalous_process_fanout":             5.0,
        "deep_process_descent":                 2.0,

        // Deep macOS internals
        "library_injection":            5.0,
        "event_tap_keylogger":          7.0,
        "task_for_pid_injection":       6.0,
        "rosetta_unsigned":             3.0,
        "sip_disabled":                 9.0,
        "non_apple_auth_plugin":        8.0,
        "rogue_xpc_service":            5.0,
        "gatekeeper_override":          3.0,
        "xprotect_outdated":            2.0,
        "suspicious_certificate":       4.0,
        "typosquat_domain":             6.0,

        // Threat intel matches
        "known_malicious_hash":         10.0,
        "known_malicious_ip":           8.0,
        "known_malicious_domain":       8.0,

        // Rule match escalation
        "sigma_rule_match_low":         1.0,
        "sigma_rule_match_medium":      2.0,
        "sigma_rule_match_high":        4.0,
        "sigma_rule_match_critical":    6.0,

        // v1.21.4 (deep-audit corr-campaign-anomaly): indicators the live
        // pipeline actually emits (EventLoop / MonitorTasks) that previously had
        // NO table entry and so silently used the 3.0 `effectiveWeight` default —
        // un-tuned and invisible to the feedback-weight machinery. Explicit
        // entries make each one tunable, and `BehaviorScoringIndicatorTests`
        // asserts every emitted indicator name has an entry here.
        "high_entropy_commandline":      3.0,   // aligned with obfuscated_commandline
        "not_notarized":                 2.0,   // weaker than unsigned_binary (much legit software isn't notarized)
        "ai_tool_unapproved_network":    2.0,   // the chatty indicator the 120s cooldown targets
        "mcp_server_suspicious":         4.0,
        "anomalous_process_tree":        4.0,   // ProcessTreeAnalyzer Markov tree anomaly
        "statistical_frequency_anomaly": 3.0,   // StatisticalAnomalyDetector z-score drift
        "statistical_process_shape_anomaly": 3.0, // argument-count / command-entropy drift
        "fresh_package_install":         2.0,   // supply-chain freshness breadcrumb
    ]

    // Weights stay deterministic in production. An earlier, unwired API
    // claimed to learn from alert suppression, but no durable mapping existed
    // from an operator verdict back to the exact indicator set and model
    // version that produced an alert. Enabling that code would therefore make
    // host-local behavior irreproducible and let dismissals silently weaken
    // detections. Adaptive weights belong behind the versioned evaluation rail
    // and an explicit promote/rollback workflow; until then the shipped table
    // above is the sole source of weight authority.

    // MARK: - Initialization

    public init(
        alertThreshold: Double = 10.0,
        criticalThreshold: Double = 20.0,
        decayHalfLife: TimeInterval = 300, // 5 minutes
        maxTrackedProcesses: Int = 5000
    ) {
        self.alertThreshold = alertThreshold
        self.criticalThreshold = criticalThreshold
        self.decayHalfLife = decayHalfLife
        self.maxTrackedProcesses = maxTrackedProcesses
    }

    // MARK: - Public API

    /// Add an indicator to a process's behavioral score.
    /// Returns a ScoringResult if the score crossed the alert threshold.
    @discardableResult
    public func addIndicator(
        _ indicator: Indicator,
        forProcess pid: Int32,
        path: String
    ) -> ScoringResult? {
        let key = ProcessKey(pid: pid, path: path)

        // Initialize or get existing score
        var addedNewKey = false
        if processScores[key] == nil {
            processScores[key] = ProcessScore()
            insertionOrder.append(key)
            addedNewKey = true
        }

        // Apply time decay to existing score
        applyDecay(for: key)

        guard var entry = processScores[key] else { return nil }

        // If score has decayed below the alert threshold, allow re-alerting.
        // This uses the full alertThreshold (not a fraction) so that the re-alert
        // condition is consistent with the firing condition — no dead zone where
        // new indicators are silently ignored.
        if entry.rawScore < alertThreshold {
            alerted.remove(key)
            abandonPendingThreshold(for: key)
        }

        // Indicator cooldown: a single indicator of the same name contributes
        // at most once per `indicatorCooldown` seconds per process. Different
        // indicators still accumulate freely — the goal is to prevent a single
        // repeating benign signal (e.g. "ai_tool_unapproved_network" firing
        // on every HTTPS request) from walking the score up on its own.
        let now = Date()
        if let last = entry.indicatorLastAdd[indicator.name],
           now.timeIntervalSince(last) < Self.indicatorCooldown {
            return pendingThresholds[key]
        }
        entry.indicatorLastAdd[indicator.name] = now

        // v1.12.0 dev-mode gate: when MACCRAB_DEV_MODE=1, halve the
        // contribution of `ai_tool_*` indicators. Rationale: on a
        // developer's machine, Claude Code / Cursor / Cline run all
        // day and legitimately spawn shells, run sudo, install
        // packages, modify shell rc files. Their full weights walk
        // the score past the 10/20 alert/critical thresholds in
        // normal operation. Halved weights still catch genuinely
        // adversarial AI-agent behavior (cumulative >2-3 hits) but
        // don't fire on the operator's everyday agent use.
        var effectiveWeight = indicator.weight
        if Self.devMode && indicator.name.hasPrefix("ai_tool_") {
            effectiveWeight = indicator.weight / 2.0
        }

        // Add the new indicator
        entry.rawScore += effectiveWeight
        entry.lastUpdate = now
        entry.indicators.append(indicator)

        // Cap indicators per process
        if entry.indicators.count > 50 {
            entry.indicators.removeFirst()
        }

        processScores[key] = entry

        // Evict AFTER the new entry's score is applied. Evicting in the
        // new-key block above (before the indicator weight lands) would make
        // a brand-new process the lowest-scored entry (rawScore 0) and
        // self-evict it the instant the table hit the cap — freezing the
        // table at its first `maxTrackedProcesses` entries and silently
        // dropping every later process, including a high-score attacker.
        // With the score applied first, the genuinely-lowest entry is evicted.
        if addedNewKey { evictIfNeeded() }
        let score = entry

        // Check threshold
        if let pending = pendingThresholds[key] {
            return pending
        }

        if score.rawScore >= alertThreshold && !alerted.contains(key) {

            let severity: Severity
            if score.rawScore >= criticalThreshold {
                severity = .critical
            } else {
                severity = .high
            }

            nextThresholdToken &+= 1
            // Keep zero reserved as an unmistakable invalid/default token even
            // after UInt64 wrap in an unrealistically long-lived process.
            if nextThresholdToken == 0 { nextThresholdToken = 1 }
            let result = ScoringResult(
                deliveryToken: nextThresholdToken,
                processPath: path,
                pid: pid,
                totalScore: score.rawScore,
                indicators: score.indicators.map { ($0.name, $0.weight, $0.detail) },
                severity: severity
            )

            pendingThresholds[key] = result
            thresholdTokenToProcess[result.deliveryToken] = key
            thresholdCrossingsTotal &+= 1

            logger.warning("Behavioral score threshold crossed: \(path) (PID \(pid)) score=\(score.rawScore)")
            return result
        }

        return nil
    }

    /// Resolve one exact pending crossing. Unknown/stale tokens are rejected so
    /// a late completion cannot spend a newer process generation's latch.
    @discardableResult
    public func resolveThreshold(
        deliveryToken: UInt64,
        as resolution: ThresholdResolution
    ) -> Bool {
        guard let key = thresholdTokenToProcess.removeValue(
            forKey: deliveryToken
        ), pendingThresholds[key]?.deliveryToken == deliveryToken else {
            return false
        }
        pendingThresholds.removeValue(forKey: key)
        alerted.insert(key)
        switch resolution {
        case .committed:
            thresholdCommittedTotal &+= 1
        case .filteredOrSuppressed:
            thresholdSuppressedTotal &+= 1
        }
        return true
    }

    /// A storage/output failure is observable but intentionally does not resolve
    /// the token. The next indicator for this process returns the same crossing
    /// and retries without inflating the score or minting a duplicate token.
    public func recordThresholdDeliveryFailure(deliveryToken: UInt64) {
        guard thresholdTokenToProcess[deliveryToken] != nil else { return }
        thresholdDeliveryFailuresTotal &+= 1
    }

    public func thresholdTelemetry() -> ThresholdTelemetry {
        ThresholdTelemetry(
            crossings: thresholdCrossingsTotal,
            committed: thresholdCommittedTotal,
            filteredOrSuppressed: thresholdSuppressedTotal,
            abandoned: thresholdAbandonedTotal,
            pending: pendingThresholds.count,
            deliveryFailures: thresholdDeliveryFailuresTotal
        )
    }

    /// Convenience: add a standard indicator by name.
    @discardableResult
    public func addIndicator(
        named name: String,
        detail: String = "",
        forProcess pid: Int32,
        path: String
    ) -> ScoringResult? {
        let weight = Self.weights[name] ?? 3.0
        return addIndicator(
            Indicator(name: name, weight: weight, detail: detail),
            forProcess: pid,
            path: path
        )
    }

    /// Add score for a Sigma rule match (escalates behavioral score based on rule severity).
    ///
    /// v1.4.5: skip contributions from processes inside trusted
    /// browser / Electron bundles. Field data showed Chrome Helper
    /// accumulating behavioral score 10+ from three back-to-back
    /// `sigma_rule_match_critical` hits that were themselves false
    /// positives on the pre-v1.3.11 compiler bug — a Behavioral
    /// Score Threshold alert on Google Chrome Helper. NoiseFilter
    /// Gate 3 already drops non-critical matches on trusted
    /// browsers, and critical-level matches almost never apply
    /// to browser helpers legitimately (real credential theft from
    /// Chrome goes through a dropper, not Chrome itself). Drop the
    /// contribution at the score-accumulation source so the user
    /// never sees "Google Chrome Helper accumulated suspicious
    /// behavior score of 10.8" from these rule FPs.
    @discardableResult
    public func addRuleMatch(
        severity: Severity,
        ruleTitle: String,
        forProcess pid: Int32,
        path: String
    ) -> ScoringResult? {
        if NoiseFilter.isTrustedBrowserHelper(path: path) {
            return nil
        }
        let indicatorName: String
        switch severity {
        case .low:           indicatorName = "sigma_rule_match_low"
        case .medium:        indicatorName = "sigma_rule_match_medium"
        case .high:          indicatorName = "sigma_rule_match_high"
        case .critical:      indicatorName = "sigma_rule_match_critical"
        case .informational: return nil
        }
        return addIndicator(named: indicatorName, detail: ruleTitle, forProcess: pid, path: path)
    }

    /// Get the current score for a process.
    public func score(forPid pid: Int32, path: String) -> Double {
        let key = ProcessKey(pid: pid, path: path)
        guard let s = processScores[key] else { return 0 }
        return decayedScore(s)
    }

    /// Get the top N scored processes.
    public func topProcesses(limit: Int = 10) -> [(path: String, pid: Int32, score: Double, indicators: Int)] {
        processScores.map { (key, score) in
            (key.path, key.pid, decayedScore(score), score.indicators.count)
        }
        .sorted { $0.2 > $1.2 }
        .prefix(limit)
        .map { ($0.0, $0.1, $0.2, $0.3) }
    }

    /// Prune expired entries.
    public func prune() {
        let now = Date()
        let expiry = decayHalfLife * 10 // Fully expired after 10 half-lives
        processScores = processScores.filter { _, score in
            now.timeIntervalSince(score.lastUpdate) < expiry
        }
        insertionOrder = insertionOrder.filter { processScores[$0] != nil }
        alerted = alerted.filter { processScores[$0] != nil }
        for key in Array(pendingThresholds.keys)
        where processScores[key] == nil {
            abandonPendingThreshold(for: key)
        }
    }

    // MARK: - Private

    private func applyDecay(for key: ProcessKey) {
        guard var score = processScores[key] else { return }
        let now = Date()
        let elapsed = now.timeIntervalSince(score.lastUpdate)
        if elapsed > 0 {
            let decayFactor = pow(0.5, elapsed / decayHalfLife)
            score.rawScore *= decayFactor
            // Advance the decay clock every time decay is applied. `applyDecay`
            // runs on EVERY addIndicator call — including cooldown-suppressed
            // calls that return early (below) without reaching the successful-add
            // path that sets `lastUpdate`. Without resetting the clock here, each
            // suppressed call re-decays from the same stale `lastUpdate`, so the
            // decay compounds quadratically (0.5^(Σ elapsed) instead of one
            // 0.5^(elapsed) step) and crushes the score far below its true value —
            // a slow-burn process whose one indicator repeats (the exact case the
            // 120s cooldown was added for) never reaches alertThreshold.
            score.lastUpdate = now
            processScores[key] = score
        }
    }

    private func decayedScore(_ score: ProcessScore) -> Double {
        let elapsed = Date().timeIntervalSince(score.lastUpdate)
        return score.rawScore * pow(0.5, elapsed / decayHalfLife)
    }

    private func evictIfNeeded() {
        // Evict the entry with the LOWEST decayed score, not the oldest-inserted
        // one. A long-lived, high-score process (e.g. a slow-burn attacker) must
        // survive churn from transient benign processes — FIFO eviction would
        // silently drop the strongest detection signal we have. Among equal
        // scores we fall back to insertion order (oldest first) for a stable,
        // deterministic choice. Eviction only runs above the cap (cold path),
        // so the O(n) scan is not on the per-event hot path.
        while processScores.count > maxTrackedProcesses {
            var victim: ProcessKey?
            var lowest = Double.greatestFiniteMagnitude
            for key in insertionOrder {
                guard let score = processScores[key] else { continue }
                let decayed = decayedScore(score)
                if decayed < lowest {
                    lowest = decayed
                    victim = key
                }
            }
            guard let evict = victim else { break }
            processScores.removeValue(forKey: evict)
            alerted.remove(evict)
            abandonPendingThreshold(for: evict)
            if let idx = insertionOrder.firstIndex(of: evict) {
                insertionOrder.remove(at: idx)
            }
        }
    }

    private func abandonPendingThreshold(for key: ProcessKey) {
        guard let pending = pendingThresholds.removeValue(forKey: key) else {
            return
        }
        thresholdTokenToProcess.removeValue(forKey: pending.deliveryToken)
        thresholdAbandonedTotal &+= 1
    }
}
