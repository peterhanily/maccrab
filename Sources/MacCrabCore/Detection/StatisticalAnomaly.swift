// StatisticalAnomaly.swift
// MacCrabCore
//
// Statistical anomaly detection using Welford's online algorithm for
// rolling mean/stddev tracking. Detects behavioral drift in processes
// that fixed-weight scoring misses.

import Foundation
import os.log

/// Tracks per-process statistical baselines and flags deviations.
public actor StatisticalAnomalyDetector {

    private let logger = Logger(subsystem: "com.maccrab", category: "statistical-anomaly")

    /// Z-score threshold for anomaly flagging.
    private let zThreshold: Double

    /// Minimum observations before anomaly detection activates.
    private let minSamples: Int

    /// Per-process rolling statistics.
    private var processStats: [String: ProcessStats] = [:]

    /// Maximum tracked processes.
    private let maxTracked: Int

    // MARK: - Types

    /// Welford's online algorithm for numerically stable running mean/variance.
    struct RunningStats {
        var count: Int = 0
        var mean: Double = 0
        var m2: Double = 0

        mutating func update(_ value: Double) {
            count += 1
            let delta = value - mean
            mean += delta / Double(count)
            let delta2 = value - mean
            m2 += delta * delta2
        }

        var variance: Double {
            count < 2 ? 0 : m2 / Double(count - 1)
        }

        var stddev: Double {
            sqrt(variance)
        }

        func zScore(_ value: Double) -> Double {
            let sd = stddev
            if sd <= 0 {
                // No variance yet — if value differs from mean, it's anomalous
                return abs(value - mean) > 0.001 ? 10.0 : 0.0
            }
            return abs(value - mean) / sd
        }
    }

    struct ProcessStats {
        var eventFrequency: RunningStats = .init()    // events per minute
        var connectionRate: RunningStats = .init()     // connections per minute
        var fileWriteRate: RunningStats = .init()      // file writes per minute
        var argCount: RunningStats = .init()           // argument count
        var argEntropy: RunningStats = .init()         // command-line entropy
        var lastEventTime: Date?
        var eventCountInWindow: Int = 0
        var windowStart: Date = Date()
    }

    /// Result of a statistical anomaly check.
    public struct AnomalyResult: Sendable {
        public let processPath: String
        public let feature: String
        public let value: Double
        public let mean: Double
        public let stddev: Double
        public let zScore: Double
    }

    // MARK: - Initialization

    public init(zThreshold: Double = 3.0, minSamples: Int = 50, maxTracked: Int = 5000) {
        self.zThreshold = zThreshold
        self.minSamples = minSamples
        self.maxTracked = maxTracked
    }

    // MARK: - Public API

    /// Process an event and check for statistical anomalies.
    /// Returns any anomalies detected (may be empty).
    public func processEvent(
        processPath: String,
        argCount: Int,
        commandLine: String,
        category: String,
        timestamp: Date
    ) -> [AnomalyResult] {
        // Initialize if new
        if processStats[processPath] == nil {
            if processStats.count >= maxTracked {
                // Evict least recently seen
                if let oldest = processStats.min(by: { ($0.value.lastEventTime ?? .distantPast) < ($1.value.lastEventTime ?? .distantPast) })?.key {
                    processStats.removeValue(forKey: oldest)
                }
            }
            processStats[processPath] = ProcessStats()
        }

        var stats = processStats[processPath]!
        var anomalies: [AnomalyResult] = []
        let now = timestamp

        // Track inter-event interval → event frequency
        if let lastTime = stats.lastEventTime {
            let interval = now.timeIntervalSince(lastTime)
            if interval > 0 && interval < 300 { // Ignore gaps > 5 minutes
                let eventsPerMinute = 60.0 / interval
                let z = stats.eventFrequency.zScore(eventsPerMinute)
                stats.eventFrequency.update(eventsPerMinute)

                if stats.eventFrequency.count >= minSamples && z > zThreshold {
                    anomalies.append(AnomalyResult(
                        processPath: processPath,
                        feature: "event_frequency",
                        value: eventsPerMinute,
                        mean: stats.eventFrequency.mean,
                        stddev: stats.eventFrequency.stddev,
                        zScore: z
                    ))
                }
            }
        }
        stats.lastEventTime = now

        // Track argument count
        let argZ = stats.argCount.zScore(Double(argCount))
        stats.argCount.update(Double(argCount))
        if stats.argCount.count >= minSamples && argZ > zThreshold && argCount > 5 {
            anomalies.append(AnomalyResult(
                processPath: processPath,
                feature: "argument_count",
                value: Double(argCount),
                mean: stats.argCount.mean,
                stddev: stats.argCount.stddev,
                zScore: argZ
            ))
        }

        // Track command-line entropy
        let entropy = EntropyAnalysis.shannonEntropy(commandLine)
        let entropyZ = stats.argEntropy.zScore(entropy)
        stats.argEntropy.update(entropy)
        if stats.argEntropy.count >= minSamples && entropyZ > zThreshold && entropy > 4.5 {
            anomalies.append(AnomalyResult(
                processPath: processPath,
                feature: "commandline_entropy",
                value: entropy,
                mean: stats.argEntropy.mean,
                stddev: stats.argEntropy.stddev,
                zScore: entropyZ
            ))
        }

        processStats[processPath] = stats
        return anomalies
    }

    /// Get statistics summary for a process.
    public func stats(for processPath: String) -> (
        eventFreqMean: Double, eventFreqStddev: Double,
        argCountMean: Double, argEntropyMean: Double,
        samples: Int
    )? {
        guard let s = processStats[processPath] else { return nil }
        return (
            s.eventFrequency.mean, s.eventFrequency.stddev,
            s.argCount.mean, s.argEntropy.mean,
            s.eventFrequency.count
        )
    }

    /// Prune stale process entries.
    public func prune(olderThan: TimeInterval = 3600) {
        let cutoff = Date().addingTimeInterval(-olderThan)
        processStats = processStats.filter { _, stats in
            (stats.lastEventTime ?? .distantPast) > cutoff
        }
    }
}
