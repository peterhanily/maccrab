// TopologyAnomalyDetector.swift
// MacCrabCore
//
// Shape-based process-tree anomaly detection. Complements ProcessTreeAnalyzer
// (which is probabilistic — learned Markov transitions on names) by catching
// attacks that use well-known binaries in unusual topologies. This class of
// detection is specifically a gap in commercial macOS EDRs: Sigma rules
// match single events, Markov chains score name transitions, neither catches
// "legitimate tool executed in an illegitimate shape."
//
// Fires on three categorical invariants that are near-zero in normal use but
// common in attack playbooks:
//
//   1. `launchd_spawned_shell` — /sbin/launchd directly spawning /bin/sh,
//      /bin/bash, /bin/zsh, etc. Should never happen on a healthy system;
//      when it does, it's typically a persistence payload calling back.
//
//   2. `system_process_spawning_staged_binary` — a parent under /System/ or
//      /usr/libexec/ spawning a binary in /tmp, /private/tmp, /var/tmp,
//      /Users/Shared, or ~/Downloads. These are classic malware staging
//      paths; Apple binaries have no business running them.
//
//   3. `anomalous_process_fanout` — 20+ children from the same parent PID
//      within 10 seconds. Catches fork storms, mass-scanning loops, and
//      compromised servers issuing bursts of reconnaissance commands.
//
// Plus a weaker signal (adds to BehaviorScoring but not its own critical
// event):
//
//   4. `deep_process_descent` — process lineage > 15 ancestors deep. Correlates
//      with obfuscated execution chains and nested interpreter invocations.

import Foundation
import Darwin
import os.log

public actor TopologyAnomalyDetector {

    private let logger = Logger(subsystem: "com.maccrab.detection", category: "TopologyAnomalyDetector")

    /// Categories of topology anomaly. Each maps to a distinct BehaviorScoring
    /// indicator so the dashboard can suppress / triage them independently.
    public enum AnomalyKind: String, Sendable {
        case launchdSpawnedShell              = "launchd_spawned_shell"
        case systemProcessSpawningStagedBinary = "system_process_spawning_staged_binary"
        case anomalousProcessFanout           = "anomalous_process_fanout"
        case deepProcessDescent               = "deep_process_descent"
    }

    public struct Finding: Sendable {
        public let kind: AnomalyKind
        public let detail: String
        public let processPath: String
        public let parentPath: String?
    }

    // MARK: - State (actor-isolated)

    /// Per-parent child-count window for `anomalousProcessFanout` detection.
    /// Keyed by parent PID. Each entry tracks count and window start.
    private var fanoutCounts: [pid_t: (count: Int, windowStart: Date)] = [:]

    /// Configuration knobs. Exposed for future tuning but hard-coded to sensible
    /// defaults today — shape anomalies aren't volume-sensitive so these rarely
    /// need per-deployment tuning.
    private let fanoutWindow: TimeInterval = 10
    private let fanoutThreshold: Int = 20
    private let deepDescentThreshold: Int = 15
    private let fanoutMapMaxSize: Int = 1000  // cap so a pid_t-churning bug can't OOM

    public init() {}

    // MARK: - Public API

    /// Evaluate a process-creation event against all topology invariants.
    /// Returns any findings; caller routes them to `BehaviorScoring.addIndicator`
    /// so they flow through the normal alert generation pipeline.
    ///
    /// Intentionally takes simple primitives rather than the full Event type
    /// so this detector stays trivially unit-testable.
    public func evaluate(
        processPath: String,
        processPID: pid_t,
        parentPath: String?,
        parentPID: pid_t,
        ancestryDepth: Int
    ) -> [Finding] {
        var findings: [Finding] = []

        // Invariant 1: launchd spawning a shell.
        if let parent = parentPath, Self.isLaunchd(parent), Self.isShell(processPath) {
            findings.append(Finding(
                kind: .launchdSpawnedShell,
                detail: "launchd directly spawned \(Self.basename(processPath)) — persistence callback signature",
                processPath: processPath,
                parentPath: parent
            ))
        }

        // Invariant 2: System-path parent spawning staged-binary child.
        if let parent = parentPath,
           Self.isSystemProcess(parent),
           Self.isStagedBinaryLocation(processPath) {
            findings.append(Finding(
                kind: .systemProcessSpawningStagedBinary,
                detail: "\(Self.basename(parent)) spawned \(processPath) (malware staging dir)",
                processPath: processPath,
                parentPath: parent
            ))
        }

        // Invariant 3: anomalous fanout.
        let now = Date()
        if let existing = fanoutCounts[parentPID] {
            if now.timeIntervalSince(existing.windowStart) > fanoutWindow {
                // Window expired, start fresh
                fanoutCounts[parentPID] = (1, now)
            } else {
                let newCount = existing.count + 1
                fanoutCounts[parentPID] = (newCount, existing.windowStart)
                // Fire exactly once per window when threshold is crossed.
                if newCount == fanoutThreshold {
                    findings.append(Finding(
                        kind: .anomalousProcessFanout,
                        detail: "\(newCount) children from \(Self.basename(parentPath ?? "pid \(parentPID)")) in ≤\(Int(fanoutWindow))s",
                        processPath: processPath,
                        parentPath: parentPath
                    ))
                }
            }
        } else {
            fanoutCounts[parentPID] = (1, now)
        }

        // Emergency cap — if something's leaking pids, don't grow forever.
        if fanoutCounts.count > fanoutMapMaxSize {
            // Drop the oldest half. Cheap; only happens in pathological scenarios.
            let cutoff = fanoutMapMaxSize / 2
            let sorted = fanoutCounts.sorted { $0.value.windowStart < $1.value.windowStart }
            fanoutCounts = Dictionary(uniqueKeysWithValues: sorted.suffix(cutoff).map { ($0.key, $0.value) })
            logger.warning("TopologyAnomalyDetector fanout map reached \(self.fanoutMapMaxSize); pruned oldest half")
        }

        // Invariant 4 (weaker signal): deep descent.
        if ancestryDepth > deepDescentThreshold {
            findings.append(Finding(
                kind: .deepProcessDescent,
                detail: "process depth \(ancestryDepth) (threshold \(self.deepDescentThreshold)) — possible obfuscated exec chain",
                processPath: processPath,
                parentPath: parentPath
            ))
        }

        return findings
    }

    /// Drop stale fanout entries. Called by the daemon's maintenance timer so
    /// dead PIDs don't pin memory. The evaluate() path already evicts on
    /// window expiry for parents that keep spawning — this catches parents
    /// that went quiet.
    public func purgeStale() {
        let now = Date()
        fanoutCounts = fanoutCounts.filter { _, v in
            now.timeIntervalSince(v.windowStart) < fanoutWindow * 3
        }
    }

    /// Expose current tracking size for dashboards / debug.
    public var trackingSize: Int { fanoutCounts.count }

    // MARK: - Heuristics (nonisolated — pure functions)

    private nonisolated static func isLaunchd(_ path: String) -> Bool {
        path == "/sbin/launchd" || path.hasSuffix("/launchd")
    }

    private nonisolated static func isShell(_ path: String) -> Bool {
        // Match canonical shell paths plus suffix-match for the same name under
        // /usr/local/bin, /opt/homebrew/bin, etc. We intentionally don't match
        // /usr/bin/env — that's used legitimately as a shebang target and its
        // exec target is the actual shell we'd catch.
        let shellBasenames: Set<String> = ["bash", "zsh", "sh", "dash", "ksh", "tcsh", "fish"]
        let base = basename(path)
        return shellBasenames.contains(base)
    }

    private nonisolated static func isSystemProcess(_ path: String) -> Bool {
        path.hasPrefix("/System/") ||
        path.hasPrefix("/usr/libexec/") ||
        path.hasPrefix("/usr/sbin/") ||
        path.hasPrefix("/sbin/")
    }

    /// True if the path is in a location a user (or local attacker) can write
    /// without root — i.e., a classic malware staging area. Intentionally
    /// narrow; we don't want to flag a user running a homebrew binary.
    private nonisolated static func isStagedBinaryLocation(_ path: String) -> Bool {
        path.hasPrefix("/tmp/") ||
        path.hasPrefix("/private/tmp/") ||
        path.hasPrefix("/var/tmp/") ||
        path.hasPrefix("/Users/Shared/") ||
        path.contains("/Downloads/") ||
        path.contains("/.Trash/")
    }

    private nonisolated static func basename(_ path: String) -> String {
        (path as NSString).lastPathComponent
    }
}
