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
        public let processPath: String
        public let pid: Int32
        public let totalScore: Double
        public let indicators: [(name: String, weight: Double, detail: String)]
        public let severity: Severity
    }

    // MARK: - Indicator Weights

    /// Standard indicator weights. Higher = more suspicious.
    public static let weights: [String: Double] = [
        // Process indicators
        "unsigned_binary":              3.0,
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
    ]

    // MARK: - Weight Adjustment (learning from suppression feedback)

    /// Adjusted weights: starts as a copy of `weights`, modified by feedback.
    private var adjustedWeights: [String: Double] = weights

    /// Per-indicator feedback counts: (alerts_fired, alerts_suppressed).
    private var indicatorFeedback: [String: (fired: Int, suppressed: Int)] = [:]

    /// Record that an alert containing these indicators was suppressed (FP signal).
    /// Gradually decreases weights for frequently-suppressed indicators.
    public func recordSuppression(indicatorNames: [String]) {
        for name in indicatorNames {
            indicatorFeedback[name, default: (fired: 0, suppressed: 0)].suppressed += 1
            adjustWeight(name)
        }
    }

    /// Record that an alert containing these indicators was investigated (TP signal).
    public func recordInvestigation(indicatorNames: [String]) {
        for name in indicatorNames {
            indicatorFeedback[name, default: (fired: 0, suppressed: 0)].fired += 1
            adjustWeight(name)
        }
    }

    /// Adjust weight using EMA of suppression rate.
    /// If >60% of alerts are suppressed for an indicator, reduce its weight.
    /// If <20% are suppressed, slightly increase it (up to 1.5x original).
    private func adjustWeight(_ name: String) {
        guard let feedback = indicatorFeedback[name] else { return }
        let total = feedback.fired + feedback.suppressed
        guard total >= 5 else { return } // Need enough data

        let suppressionRate = Double(feedback.suppressed) / Double(total)
        let originalWeight = Self.weights[name] ?? 3.0

        if suppressionRate > 0.6 {
            // High FP rate: reduce weight (min 20% of original)
            adjustedWeights[name] = max(originalWeight * 0.2, adjustedWeights[name, default: originalWeight] * 0.9)
        } else if suppressionRate < 0.2 {
            // Low FP rate: slightly boost (max 1.5x original)
            adjustedWeights[name] = min(originalWeight * 1.5, adjustedWeights[name, default: originalWeight] * 1.05)
        }
    }

    /// Get the effective weight for an indicator (adjusted if feedback exists).
    public func effectiveWeight(for name: String) -> Double {
        adjustedWeights[name] ?? Self.weights[name] ?? 3.0
    }

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
        if processScores[key] == nil {
            processScores[key] = ProcessScore()
            insertionOrder.append(key)
            evictIfNeeded()
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
        }

        // Indicator cooldown: a single indicator of the same name contributes
        // at most once per `indicatorCooldown` seconds per process. Different
        // indicators still accumulate freely — the goal is to prevent a single
        // repeating benign signal (e.g. "ai_tool_unapproved_network" firing
        // on every HTTPS request) from walking the score up on its own.
        let now = Date()
        if let last = entry.indicatorLastAdd[indicator.name],
           now.timeIntervalSince(last) < Self.indicatorCooldown {
            return nil
        }
        entry.indicatorLastAdd[indicator.name] = now

        // Add the new indicator
        entry.rawScore += indicator.weight
        entry.lastUpdate = now
        entry.indicators.append(indicator)

        // Cap indicators per process
        if entry.indicators.count > 50 {
            entry.indicators.removeFirst()
        }

        processScores[key] = entry
        let score = entry

        // Check threshold
        if score.rawScore >= alertThreshold && !alerted.contains(key) {
            alerted.insert(key)

            let severity: Severity
            if score.rawScore >= criticalThreshold {
                severity = .critical
            } else {
                severity = .high
            }

            let result = ScoringResult(
                processPath: path,
                pid: pid,
                totalScore: score.rawScore,
                indicators: score.indicators.map { ($0.name, $0.weight, $0.detail) },
                severity: severity
            )

            logger.warning("Behavioral score threshold crossed: \(path) (PID \(pid)) score=\(score.rawScore)")
            return result
        }

        return nil
    }

    /// Convenience: add a standard indicator by name.
    @discardableResult
    public func addIndicator(
        named name: String,
        detail: String = "",
        forProcess pid: Int32,
        path: String
    ) -> ScoringResult? {
        let weight = effectiveWeight(for: name)
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
    }

    // MARK: - Private

    private func applyDecay(for key: ProcessKey) {
        guard var score = processScores[key] else { return }
        let elapsed = Date().timeIntervalSince(score.lastUpdate)
        if elapsed > 0 {
            let decayFactor = pow(0.5, elapsed / decayHalfLife)
            score.rawScore *= decayFactor
            processScores[key] = score
        }
    }

    private func decayedScore(_ score: ProcessScore) -> Double {
        let elapsed = Date().timeIntervalSince(score.lastUpdate)
        return score.rawScore * pow(0.5, elapsed / decayHalfLife)
    }

    private func evictIfNeeded() {
        while processScores.count > maxTrackedProcesses, let oldest = insertionOrder.first {
            processScores.removeValue(forKey: oldest)
            alerted.remove(oldest)
            insertionOrder.removeFirst()
        }
    }
}
