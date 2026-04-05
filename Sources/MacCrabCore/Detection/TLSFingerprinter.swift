// TLSFingerprinter.swift
// MacCrabCore
//
// Lightweight TLS traffic analysis for detecting malicious C2 patterns.
// Since raw TLS inspection requires a Network Extension, this module uses
// heuristic analysis of connection patterns instead of actual JA3/JA4 hashing:
//   1. Known C2 framework port fingerprints
//   2. Non-browser processes on suspicious HTTPS ports
//   3. Beacon detection via regular-interval connection analysis

import Foundation
import os.log

/// Lightweight TLS traffic analysis for detecting malicious C2 patterns.
///
/// Since raw TLS inspection requires a Network Extension, this module uses
/// heuristic analysis of connection patterns instead of actual JA3/JA4 hashing.
public actor TLSFingerprinter {

    private let logger = Logger(subsystem: "com.maccrab.detection", category: "tls-fingerprint")

    // MARK: - Types

    /// Known C2 framework TLS patterns (process behavior, not actual JA4 hashes).
    /// These are behavioral fingerprints: connection timing, port patterns, cert patterns.
    public struct TLSPattern: Sendable {
        public let name: String           // C2 framework name
        public let description: String
        public let ports: Set<UInt16>     // Typical ports used
        public let beaconIntervalRange: ClosedRange<TimeInterval>?  // Beacon timing
    }

    /// Alert emitted when a TLS connection matches C2 indicators.
    public struct TLSAlert: Sendable {
        public let alertType: AlertType
        public let processName: String
        public let processPath: String
        public let destinationIP: String
        public let destinationPort: UInt16
        public let detail: String
        public let severity: Severity

        public enum AlertType: String, Sendable {
            case suspiciousPort = "suspicious_tls_port"
            case beaconDetected = "c2_beacon_detected"
            case knownC2Port = "known_c2_port"
        }
    }

    // MARK: - Known C2 Patterns

    /// Known C2 behavioral patterns.
    private static let c2Patterns: [TLSPattern] = [
        TLSPattern(name: "Cobalt Strike", description: "Default Cobalt Strike beacon pattern",
                   ports: [443, 8443, 50050], beaconIntervalRange: 55...65),
        TLSPattern(name: "Sliver", description: "Sliver C2 implant pattern",
                   ports: [443, 8888, 31337], beaconIntervalRange: nil),
        TLSPattern(name: "Mythic", description: "Mythic C2 agent pattern",
                   ports: [443, 7443, 8443], beaconIntervalRange: nil),
        TLSPattern(name: "Metasploit", description: "Meterpreter reverse HTTPS",
                   ports: [443, 4443, 8443, 8080], beaconIntervalRange: nil),
        TLSPattern(name: "Havoc", description: "Havoc C2 demon pattern",
                   ports: [443, 40056], beaconIntervalRange: nil),
    ]

    /// Suspicious non-standard HTTPS ports.
    private static let suspiciousHTTPSPorts: Set<UInt16> = [
        4443, 8443, 8080, 8888, 9443,
        31337, 40056, 50050, 55553,
    ]

    /// Browsers and system processes that legitimately make TLS connections.
    private static let allowedProcesses: Set<String> = [
        "Google Chrome", "Google Chrome Helper",
        "firefox", "Safari",
        "com.apple.WebKit.Networking",
        "Microsoft Edge", "Arc", "Brave Browser",
    ]

    // MARK: - State

    /// Per-process connection history for beacon detection.  Key: "processPath:destinationIP".
    private var connectionHistory: [String: [Date]] = [:]
    private let maxHistoryPerProcess = 100
    private let beaconWindowSeconds: TimeInterval = 600  // 10-minute analysis window

    // MARK: - Initialization

    public init() {}

    // MARK: - Analysis

    /// Analyze a TLS/HTTPS connection for C2 indicators.
    ///
    /// Call this for every outbound TLS connection observed via `NetworkCollector`.
    /// Returns an alert if the connection matches known C2 behavior, or `nil` if benign.
    public func analyze(
        processName: String,
        processPath: String,
        destinationIP: String,
        destinationPort: UInt16,
        timestamp: Date
    ) -> TLSAlert? {
        // Skip browsers and system processes
        let name = (processPath as NSString).lastPathComponent
        if Self.allowedProcesses.contains(name) || Self.allowedProcesses.contains(processName) {
            return nil
        }
        if processPath.hasPrefix("/System/") || processPath.hasPrefix("/usr/libexec/") {
            return nil
        }

        // Check for known C2 port patterns (only non-443 ports, since 443 is normal)
        for pattern in Self.c2Patterns {
            if pattern.ports.contains(destinationPort) && destinationPort != 443 {
                logger.warning("C2 port match: \(processName) → \(destinationIP):\(destinationPort) (\(pattern.name))")
                return TLSAlert(
                    alertType: .knownC2Port,
                    processName: processName, processPath: processPath,
                    destinationIP: destinationIP, destinationPort: destinationPort,
                    detail: "Connection to port \(destinationPort) matches \(pattern.name) C2 pattern: \(pattern.description)",
                    severity: .high
                )
            }
        }

        // Check for suspicious non-standard HTTPS ports
        if Self.suspiciousHTTPSPorts.contains(destinationPort) {
            logger.warning("Suspicious HTTPS port: \(processName) → \(destinationIP):\(destinationPort)")
            return TLSAlert(
                alertType: .suspiciousPort,
                processName: processName, processPath: processPath,
                destinationIP: destinationIP, destinationPort: destinationPort,
                detail: "Non-browser process connecting to suspicious HTTPS port \(destinationPort)",
                severity: .medium
            )
        }

        // Beacon detection: regular interval connections from same process to same dest
        if destinationPort == 443 {
            let key = "\(processPath):\(destinationIP)"
            var history = connectionHistory[key] ?? []
            history.append(timestamp)

            // Keep only recent history within the analysis window
            let cutoff = timestamp.addingTimeInterval(-beaconWindowSeconds)
            history = history.filter { $0 >= cutoff }
            if history.count > maxHistoryPerProcess {
                history = Array(history.suffix(maxHistoryPerProcess))
            }
            connectionHistory[key] = history

            // Need at least 5 connections to detect a beacon pattern
            if history.count >= 5 {
                let intervals = zip(history.dropFirst(), history).map { $0.timeIntervalSince($1) }
                let avgInterval = intervals.reduce(0, +) / Double(intervals.count)
                let variance = intervals.map { ($0 - avgInterval) * ($0 - avgInterval) }
                    .reduce(0, +) / Double(intervals.count)
                let stdDev = sqrt(variance)

                // Low variance = regular beacon (< 20% of average, between 5s and 5min)
                if stdDev < avgInterval * 0.2 && avgInterval > 5 && avgInterval < 300 {
                    logger.critical("Beacon detected: \(processName) → \(destinationIP):443 every \(String(format: "%.1f", avgInterval))s")
                    return TLSAlert(
                        alertType: .beaconDetected,
                        processName: processName, processPath: processPath,
                        destinationIP: destinationIP, destinationPort: destinationPort,
                        detail: "Regular beacon detected: \(String(format: "%.1f", avgInterval))s interval "
                            + "(±\(String(format: "%.1f", stdDev))s) over \(history.count) connections",
                        severity: .critical
                    )
                }
            }
        }

        return nil
    }

    // MARK: - Maintenance

    /// Periodic cleanup of stale connection histories.
    public func sweep() {
        let cutoff = Date().addingTimeInterval(-beaconWindowSeconds)
        connectionHistory = connectionHistory.compactMapValues { dates in
            let filtered = dates.filter { $0 >= cutoff }
            return filtered.isEmpty ? nil : filtered
        }
    }
}
