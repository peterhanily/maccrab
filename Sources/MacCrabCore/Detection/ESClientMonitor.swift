// ESClientMonitor.swift
// MacCrabCore
//
// Monitors Endpoint Security infrastructure health via observable indicators.
// Detects tampering with ES clients, slot exhaustion, and security daemon health.
//
// Checks ES health via observable side effects: whether the key security
// daemons (xprotectd, syspolicyd, endpointsecurityd) are running, and
// estimates ES client slot occupancy from known consumers.

import Foundation
import os.log

/// Monitors Endpoint Security infrastructure health via observable indicators.
/// Detects tampering with ES clients, slot exhaustion, and security daemon health.
public actor ESClientMonitor {

    private let logger = Logger(subsystem: "com.maccrab.detection", category: "es-monitor")

    public struct ESHealthStatus: Sendable {
        public let xprotectdRunning: Bool
        public let syspolicydRunning: Bool
        public let endpointsecuritydRunning: Bool
        public let estimatedFreeSlots: Int   // 3 - occupied (estimated)
        public let isHealthy: Bool
        public let issues: [String]
    }

    public struct ESHealthEvent: Sendable {
        public let type: EventType
        public let description: String
        public let severity: Severity

        public enum EventType: String, Sendable {
            case xprotectdDown = "xprotectd_down"
            case syspolicydDown = "syspolicyd_down"
            case endpointsecuritydDown = "endpointsecurityd_down"
            case slotExhaustion = "es_slot_exhaustion"
            case securityDaemonRestarted = "security_daemon_restarted"
            case healthy = "es_healthy"
        }
    }

    /// Events stream for health changes
    public nonisolated let events: AsyncStream<ESHealthEvent>
    private var continuation: AsyncStream<ESHealthEvent>.Continuation?
    private var pollTask: Task<Void, Never>?

    /// Previous health state for change detection
    private var previousXprotectd: Bool = true
    private var previousSyspolicyd: Bool = true
    private var previousEndpointsecurityd: Bool = true

    private let pollInterval: TimeInterval

    public init(pollInterval: TimeInterval = 60) {
        self.pollInterval = pollInterval
        var capturedContinuation: AsyncStream<ESHealthEvent>.Continuation!
        self.events = AsyncStream(bufferingPolicy: .bufferingNewest(32)) { continuation in
            capturedContinuation = continuation
        }
        self.continuation = capturedContinuation
    }

    public func start() {
        guard pollTask == nil else { return }
        logger.info("ES client monitor starting (poll every \(self.pollInterval)s)")

        pollTask = Task { [weak self] in
            guard let self else { return }
            while !Task.isCancelled {
                await self.checkHealth()
                try? await Task.sleep(nanoseconds: UInt64(self.pollInterval * 1_000_000_000))
            }
        }
    }

    public func stop() {
        pollTask?.cancel()
        pollTask = nil
        continuation?.finish()
    }

    /// Get current health status (one-shot, no events)
    public func currentStatus() -> ESHealthStatus {
        var issues: [String] = []

        let xprotectd = Self.isProcessRunning("xprotectd")
        let syspolicyd = Self.isProcessRunning("syspolicyd")
        let endpointsecurityd = Self.isProcessRunning("endpointsecurityd")

        if !xprotectd { issues.append("xprotectd is not running") }
        if !syspolicyd { issues.append("syspolicyd is not running") }
        if !endpointsecurityd { issues.append("endpointsecurityd is not running") }

        // Estimate free ES slots: xprotectd uses 1, third-party EDR tools use additional slots
        let occupied = (xprotectd ? 1 : 0)
            + (Self.isProcessRunning("CrowdStrike") ? 1 : 0)
            + (Self.isProcessRunning("SentinelOne") ? 1 : 0)
        let freeSlots = max(0, 3 - occupied)

        return ESHealthStatus(
            xprotectdRunning: xprotectd,
            syspolicydRunning: syspolicyd,
            endpointsecuritydRunning: endpointsecurityd,
            estimatedFreeSlots: freeSlots,
            isHealthy: issues.isEmpty,
            issues: issues
        )
    }

    // MARK: - Private

    private func checkHealth() {
        let xprotectd = Self.isProcessRunning("xprotectd")
        let syspolicyd = Self.isProcessRunning("syspolicyd")
        let endpointsecurityd = Self.isProcessRunning("endpointsecurityd")

        // Detect state changes
        if previousXprotectd && !xprotectd {
            let event = ESHealthEvent(
                type: .xprotectdDown,
                description: "xprotectd is no longer running — ES malware scanning may be disabled",
                severity: .critical
            )
            continuation?.yield(event)
            logger.critical("xprotectd DOWN — ES infrastructure compromised")
        } else if !previousXprotectd && xprotectd {
            let event = ESHealthEvent(
                type: .securityDaemonRestarted,
                description: "xprotectd restarted",
                severity: .medium
            )
            continuation?.yield(event)
        }

        if previousSyspolicyd && !syspolicyd {
            let event = ESHealthEvent(
                type: .syspolicydDown,
                description: "syspolicyd is no longer running — Gatekeeper enforcement may be disabled",
                severity: .critical
            )
            continuation?.yield(event)
            logger.critical("syspolicyd DOWN — Gatekeeper compromised")
        } else if !previousSyspolicyd && syspolicyd {
            let event = ESHealthEvent(
                type: .securityDaemonRestarted,
                description: "syspolicyd restarted",
                severity: .medium
            )
            continuation?.yield(event)
        }

        if previousEndpointsecurityd && !endpointsecurityd {
            let event = ESHealthEvent(
                type: .endpointsecuritydDown,
                description: "endpointsecurityd is no longer running — ES client management disabled",
                severity: .critical
            )
            continuation?.yield(event)
            logger.critical("endpointsecurityd DOWN")
        } else if !previousEndpointsecurityd && endpointsecurityd {
            let event = ESHealthEvent(
                type: .securityDaemonRestarted,
                description: "endpointsecurityd restarted",
                severity: .medium
            )
            continuation?.yield(event)
        }

        previousXprotectd = xprotectd
        previousSyspolicyd = syspolicyd
        previousEndpointsecurityd = endpointsecurityd
    }

    /// Check if a process is running by name using /usr/bin/pgrep (lightweight).
    private nonisolated static func isProcessRunning(_ name: String) -> Bool {
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/usr/bin/pgrep")
        proc.arguments = ["-x", name]
        proc.standardOutput = FileHandle.nullDevice
        proc.standardError = FileHandle.nullDevice
        try? proc.run()
        proc.waitUntilExit()
        return proc.terminationStatus == 0
    }
}
