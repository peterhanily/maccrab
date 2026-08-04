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

    private var observations: UInt64 = 0
    private var processShapeObservations: UInt64 = 0
    private var timingObservations: UInt64 = 0
    private var timingCoverageSkipped: UInt64 = 0
    private var outOfOrderTimestamps: UInt64 = 0
    private var emittedAnomalies: UInt64 = 0
    private var clippedBaselineUpdates: UInt64 = 0
    private var evictedIdentities: UInt64 = 0

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

        /// Keep a detected outlier from immediately teaching the baseline that
        /// the outlier is normal. A minimum feature-specific scale still lets a
        /// formerly constant baseline adapt gradually instead of freezing
        /// forever after its first legitimate change.
        mutating func updateClipped(
            _ value: Double,
            zLimit: Double,
            minimumScale: Double
        ) {
            guard count >= 2 else {
                update(value)
                return
            }
            let scale = max(stddev, minimumScale)
            let radius = max(1, zLimit) * scale
            update(min(max(value, mean - radius), mean + radius))
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
        var argCount: RunningStats = .init()           // argument count
        var argEntropy: RunningStats = .init()         // command-line entropy
        var lastTimingEventTime: Date?
        var lastActivity: Date?
        // v1.21.4 (deep-audit corr-campaign-anomaly): removed four orphaned
        // fields (connectionRate, fileWriteRate, eventCountInWindow, windowStart)
        // that were never read or updated — they implied connection/file-write
        // -rate coverage this detector does not have. Only event-frequency, arg
        // count, and command-line entropy are actually tracked (see processEvent).
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

    public struct Telemetry: Sendable, Equatable {
        public let observations: UInt64
        public let processShapeObservations: UInt64
        public let timingObservations: UInt64
        public let timingCoverageSkipped: UInt64
        public let outOfOrderTimestamps: UInt64
        public let emittedAnomalies: UInt64
        public let clippedBaselineUpdates: UInt64
        public let evictedIdentities: UInt64
        public let trackedIdentities: Int
        public let maximumTrackedIdentities: Int
    }

    // MARK: - Initialization

    public init(zThreshold: Double = 3.0, minSamples: Int = 50, maxTracked: Int = 5000) {
        self.zThreshold = max(1, zThreshold.isFinite ? zThreshold : 3.0)
        self.minSamples = max(2, minSamples)
        self.maxTracked = max(1, maxTracked)
    }

    // MARK: - Public API

    /// Process an event and check for statistical anomalies.
    /// Returns any anomalies detected (may be empty).
    /// - Parameter commandLineEntropy: A pre-computed
    ///   `EntropyAnalysis.shannonEntropy(commandLine)`. When non-nil it is used
    ///   directly instead of recomputing (the caller has already run the same
    ///   pass over the identical string). Identical input → identical value, so
    ///   the accumulated entropy statistics and any anomaly are unchanged.
    /// - Parameter binaryIdentity: Stable code identity such as a CDHash. The
    ///   executable path is the fallback when no stronger identity is present.
    /// - Parameter timingCoverageComplete: Enables frequency inference only
    ///   when the caller can prove this category was neither sampled nor
    ///   dropped. False is the safe default.
    public func processEvent(
        processPath: String,
        argCount: Int,
        commandLine: String,
        category: String,
        timestamp: Date,
        commandLineEntropy: Double? = nil,
        binaryIdentity: String? = nil,
        timingCoverageComplete: Bool = false
    ) -> [AnomalyResult] {
        observations &+= 1
        let normalizedCategory = category.lowercased()
        let key = Self.baselineKey(
            processPath: processPath,
            category: normalizedCategory,
            binaryIdentity: binaryIdentity
        )

        if processStats[key] == nil {
            if processStats.count >= maxTracked,
               let oldest = processStats.min(by: {
                   ($0.value.lastActivity ?? .distantPast)
                       < ($1.value.lastActivity ?? .distantPast)
               })?.key {
                processStats.removeValue(forKey: oldest)
                evictedIdentities &+= 1
            }
            processStats[key] = ProcessStats()
        }

        var stats = processStats[key]!
        var anomalies: [AnomalyResult] = []
        let now = timestamp

        // Delivered-event frequency under sampling/drop measures collector
        // behavior, not process behavior. Abstain unless the caller can prove
        // this category's timing stream is complete.
        if timingCoverageComplete {
            if let lastTime = stats.lastTimingEventTime {
                let rawInterval = now.timeIntervalSince(lastTime)
                if rawInterval > 0, rawInterval < 300 {
                    let eventsPerMinute = 60.0 / max(0.001, rawInterval)
                    let priorCount = stats.eventFrequency.count
                    let priorMean = stats.eventFrequency.mean
                    let priorStddev = stats.eventFrequency.stddev
                    let z = stats.eventFrequency.zScore(eventsPerMinute)
                    if priorCount >= minSamples, z > zThreshold {
                        anomalies.append(AnomalyResult(
                            processPath: processPath,
                            feature: "event_frequency",
                            value: eventsPerMinute,
                            mean: priorMean,
                            stddev: priorStddev,
                            zScore: z
                        ))
                        stats.eventFrequency.updateClipped(
                            eventsPerMinute,
                            zLimit: zThreshold,
                            minimumScale: 1
                        )
                        clippedBaselineUpdates &+= 1
                    } else {
                        stats.eventFrequency.update(eventsPerMinute)
                    }
                    timingObservations &+= 1
                } else if rawInterval <= 0 {
                    outOfOrderTimestamps &+= 1
                }
            }
            if stats.lastTimingEventTime == nil
                || now > (stats.lastTimingEventTime ?? .distantPast) {
                stats.lastTimingEventTime = now
            }
        } else {
            timingCoverageSkipped &+= 1
        }

        // Argument shape belongs to a process event. Repeating one launch's
        // args on thousands of file/network events made the baseline depend on
        // delivery mix and let file floods drown real launch changes.
        if normalizedCategory == "process" {
            processShapeObservations &+= 1
            let countValue = Double(max(0, argCount))
            let priorArgCount = stats.argCount.count
            let priorArgMean = stats.argCount.mean
            let priorArgStddev = stats.argCount.stddev
            let argZ = stats.argCount.zScore(countValue)
            if priorArgCount >= minSamples, argZ > zThreshold, argCount > 5 {
                anomalies.append(AnomalyResult(
                    processPath: processPath,
                    feature: "argument_count",
                    value: countValue,
                    mean: priorArgMean,
                    stddev: priorArgStddev,
                    zScore: argZ
                ))
                stats.argCount.updateClipped(
                    countValue,
                    zLimit: zThreshold,
                    minimumScale: 1
                )
                clippedBaselineUpdates &+= 1
            } else {
                stats.argCount.update(countValue)
            }

            let entropy = commandLineEntropy
                ?? EntropyAnalysis.shannonEntropy(commandLine)
            if entropy.isFinite {
                let priorEntropyCount = stats.argEntropy.count
                let priorEntropyMean = stats.argEntropy.mean
                let priorEntropyStddev = stats.argEntropy.stddev
                let entropyZ = stats.argEntropy.zScore(entropy)
                if priorEntropyCount >= minSamples,
                   entropyZ > zThreshold,
                   entropy > 4.5 {
                    anomalies.append(AnomalyResult(
                        processPath: processPath,
                        feature: "commandline_entropy",
                        value: entropy,
                        mean: priorEntropyMean,
                        stddev: priorEntropyStddev,
                        zScore: entropyZ
                    ))
                    stats.argEntropy.updateClipped(
                        entropy,
                        zLimit: zThreshold,
                        minimumScale: 0.1
                    )
                    clippedBaselineUpdates &+= 1
                } else {
                    stats.argEntropy.update(entropy)
                }
            }
        }

        stats.lastActivity = max(stats.lastActivity ?? .distantPast, now)
        processStats[key] = stats
        emittedAnomalies &+= UInt64(anomalies.count)
        return anomalies
    }

    private nonisolated static func baselineKey(
        processPath: String,
        category: String,
        binaryIdentity: String?
    ) -> String {
        let identity: String
        if let binaryIdentity, !binaryIdentity.isEmpty {
            identity = binaryIdentity
        } else {
            identity = processPath
        }
        return category + "\u{1F}" + identity
    }

    public func telemetry() -> Telemetry {
        Telemetry(
            observations: observations,
            processShapeObservations: processShapeObservations,
            timingObservations: timingObservations,
            timingCoverageSkipped: timingCoverageSkipped,
            outOfOrderTimestamps: outOfOrderTimestamps,
            emittedAnomalies: emittedAnomalies,
            clippedBaselineUpdates: clippedBaselineUpdates,
            evictedIdentities: evictedIdentities,
            trackedIdentities: processStats.count,
            maximumTrackedIdentities: maxTracked
        )
    }

    /// Get statistics summary for a process.
    public func stats(
        for processPath: String,
        category: String = "process",
        binaryIdentity: String? = nil
    ) -> (
        eventFreqMean: Double, eventFreqStddev: Double,
        argCountMean: Double, argEntropyMean: Double,
        samples: Int
    )? {
        let key = Self.baselineKey(
            processPath: processPath,
            category: category.lowercased(),
            binaryIdentity: binaryIdentity
        )
        guard let s = processStats[key] else { return nil }
        return (
            s.eventFrequency.mean, s.eventFrequency.stddev,
            s.argCount.mean, s.argEntropy.mean,
            max(s.eventFrequency.count, s.argCount.count, s.argEntropy.count)
        )
    }

    /// Prune stale process entries.
    public func prune(olderThan: TimeInterval = 3600, now: Date = Date()) {
        let cutoff = now.addingTimeInterval(-max(0, olderThan))
        processStats = processStats.filter { _, stats in
            (stats.lastActivity ?? .distantPast) > cutoff
        }
    }
}
