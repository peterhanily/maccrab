// SuppressionManager.swift
// MacCrabCore
//
// Loads and evaluates per-rule process suppressions from suppressions.json.
// This allows operators to allowlist specific process paths for rules that
// produce known false positives (e.g., system daemons triggering generic rules).

import Foundation
import os.log

/// Manages per-rule process suppressions loaded from a JSON config file.
///
/// The suppression file maps rule IDs to arrays of process paths that should be
/// ignored for that rule. Format:
/// ```json
/// {
///     "maccrab.deep.event-tap-keylogger": ["/usr/libexec/universalaccessd"],
///     "rule-id-2": ["/path/to/safe/process"]
/// }
/// ```
///
/// The daemon checks this before emitting alerts. The CLI (`maccrabctl suppress`)
/// writes to the same file.
public actor SuppressionManager {

    private var suppressions: [String: Set<String>] = [:]
    private let filePath: String
    private let logger = Logger(subsystem: "com.maccrab.detection", category: "SuppressionManager")

    /// Creates a suppression manager reading from the given directory.
    ///
    /// - Parameter dataDir: The MacCrab data directory containing `suppressions.json`.
    public init(dataDir: String) {
        self.filePath = (dataDir as NSString).appendingPathComponent("suppressions.json")
    }

    /// Loads suppressions from disk. Safe to call multiple times (reloads).
    public func load() {
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: filePath)) else {
            logger.info("No suppressions file at \(self.filePath)")
            return
        }
        guard let raw = try? JSONDecoder().decode([String: [String]].self, from: data) else {
            logger.warning("Failed to decode suppressions.json")
            return
        }
        suppressions = raw.mapValues { Set($0) }
        let total = suppressions.values.reduce(0) { $0 + $1.count }
        logger.info("Loaded \(self.suppressions.count) suppression rules (\(total) process paths)")
    }

    /// Returns true if the given alert should be suppressed.
    ///
    /// - Parameters:
    ///   - ruleId: The detection rule identifier.
    ///   - processPath: The executable path of the alerting process.
    /// - Returns: `true` if this process is allowlisted for this rule.
    public func isSuppressed(ruleId: String, processPath: String) -> Bool {
        guard let paths = suppressions[ruleId] else { return false }
        return paths.contains(processPath)
    }

    /// Returns the current suppression count for status display.
    public func stats() -> (ruleCount: Int, pathCount: Int) {
        let pathCount = suppressions.values.reduce(0) { $0 + $1.count }
        return (ruleCount: suppressions.count, pathCount: pathCount)
    }
}
