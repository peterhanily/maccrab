// ESClientMonitor.swift
// MacCrabCore
//
// Monitors Endpoint Security infrastructure health via observable indicators.
// Detects tampering with ES clients, slot exhaustion, and security daemon health.
//
// Checks ES health via observable side effects: whether the key security
// daemons (xprotectd, syspolicyd, endpointsecurityd) are running, and
// estimates ES client slot occupancy from known consumers. Only xprotectd is
// kept alive by launchd; endpointsecurityd and syspolicyd are launched on
// demand and idle-exit, so their absence is reported but never alerted.

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
            // v1.21.4 Phase-1 D2: the ES sensor is losing telemetry — a
            // file-event flood is spiking above baseline WHILE the kernel is
            // dropping messages (or the process/exec channel is collapsing),
            // i.e. a possible telemetry-drop evasion. Unlike the daemon-liveness
            // cases above, this is NOT emitted through `events` (the D2 meta-alert
            // is routed via AlertSink from the heartbeat tick so it inherits
            // dedup/suppression); the case exists so the alert's synthetic
            // `maccrab.self-defense.sensor_degraded` ruleId and the ES Health
            // surface share one canonical type string.
            case sensorDegraded = "sensor_degraded"
        }
    }

    /// Events stream for health changes
    public nonisolated let events: AsyncStream<ESHealthEvent>
    /// Poll completion, independent of whether a poll found a change. The
    /// monitor emits only on transitions, so its registry health used to be
    /// driven by alerts: absent until the first one, "stalled" after it.
    public nonisolated let pollingHealth = NetworkPollingHealth()
    private var continuation: AsyncStream<ESHealthEvent>.Continuation?
    private var pollTask: Task<Void, Never>?
    private var lifecyclePhase: CollectorLifecyclePhase = .initialized

    /// Previous health state for change detection
    private var previousXprotectd: Bool = true

    private let pollInterval: TimeInterval
    private let isRunning: @Sendable (String) -> Bool

    public init(pollInterval: TimeInterval = 60) {
        self.init(pollInterval: pollInterval, isRunning: Self.isProcessRunning)
    }

    init(pollInterval: TimeInterval, isRunning: @escaping @Sendable (String) -> Bool) {
        self.pollInterval = pollInterval
        self.isRunning = isRunning
        var capturedContinuation: AsyncStream<ESHealthEvent>.Continuation!
        self.events = AsyncStream(bufferingPolicy: .bufferingNewest(32)) { continuation in
            capturedContinuation = continuation
        }
        self.continuation = capturedContinuation
    }

    public func start() {
        guard lifecyclePhase == .initialized else { return }
        lifecyclePhase = .running
        guard let generation = pollingHealth.begin() else { return }
        logger.info("ES client monitor starting (poll every \(self.pollInterval)s)")

        pollTask = Task { [weak self] in
            guard let self else { return }
            while !Task.isCancelled {
                await self.checkHealth()
                self.pollingHealth.completed(generation: generation)
                try? await Task.sleep(nanoseconds: UInt64(self.pollInterval * 1_000_000_000))
            }
        }
    }

    public func stop() {
        _ = beginStop()
    }

    @discardableResult
    public func stopAndJoin(deadline: TimeInterval = 1.0) async -> Bool {
        let task = beginStop()
        let joined = await CollectorBoundedTaskJoin.waitForAll(
            task.map { [$0] } ?? [],
            deadline: deadline
        )
        if joined {
            pollTask = nil
            lifecyclePhase = .stopped
        }
        return joined
    }

    private func beginStop() -> Task<Void, Never>? {
        if lifecyclePhase == .stopped { return nil }
        lifecyclePhase = .stopping
        pollingHealth.stop()
        let task = pollTask
        pollTask?.cancel()
        continuation?.finish()
        continuation = nil
        return task
    }

    /// Get current health status (one-shot, no events)
    public func currentStatus() -> ESHealthStatus {
        var issues: [String] = []

        let xprotectd = isRunning("xprotectd")
        let syspolicyd = isRunning("syspolicyd")
        let endpointsecurityd = isRunning("endpointsecurityd")

        // syspolicyd and endpointsecurityd idle-exit by design: not issues.
        if !xprotectd { issues.append("xprotectd is not running") }

        // Estimate free ES slots: xprotectd uses 1, third-party EDR tools use additional slots
        let occupied = (xprotectd ? 1 : 0)
            + (isRunning("CrowdStrike") ? 1 : 0)
            + (isRunning("SentinelOne") ? 1 : 0)
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

    /// One poll. Internal so tests can drive transitions with a fake probe.
    ///
    /// Only xprotectd (launchd KeepAlive) is alerted on. endpointsecurityd is
    /// launched on demand and idle-exits under memory pressure while ES
    /// delivery continues (field: a CRITICAL "Endpointsecurityd Down" whose
    /// launchd exit reason was JETSAM_REASON_MEMORY_IDLE_EXIT); syspolicyd is
    /// likewise on demand. ES liveness itself is proven by ESCollector's native
    /// callbacks and coverage canary.
    func checkHealth() {
        let xprotectd = isRunning("xprotectd")

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

        previousXprotectd = xprotectd
    }

    /// Check if a process is running by name using /usr/bin/pgrep (lightweight).
    ///
    /// `try? proc.run()` followed by a blocking wait / `terminationStatus` is
    /// not merely lossy — it ABORTS the process. `Process` is NSTask, and
    /// `-[NSConcreteTask terminationStatus]` raises NSInvalidArgumentException
    /// ("task not launched") when the spawn failed; an uncaught ObjC exception
    /// in Swift is SIGABRT, here of the ROOT System Extension. `posix_spawn`
    /// returns EAGAIN whenever the per-user or system maxproc limit is
    /// exhausted — reachable by any unprivileged local user — and this poll runs
    /// 3× every 60 s (5× including the slot estimate), so the window is
    /// continuous.
    ///
    /// Fail SAFE rather than fatal OR alarmist: report "running". A spawn we
    /// could not perform is no evidence about the target, and the caller turns
    /// `false` into a CRITICAL "xprotectd DOWN — ES infrastructure compromised"
    /// alert. Returning `false` here would convert process-table pressure into a
    /// self-inflicted critical-alert storm.
    ///
    /// pgrep exits 1 when nothing matched and 2/3 on its own errors; only 1 is
    /// evidence that the process is absent.
    nonisolated static func isProcessRunning(_ name: String) -> Bool {
        guard let result = BoundedPrivilegedProcessRunner.run(
            executable: "/usr/bin/pgrep",
            arguments: ["-x", name],
            timeout: 2,
            maximumOutputBytes: nil
        ) else {
            Logger(subsystem: "com.maccrab.detection", category: "es-monitor")
                .error("bounded pgrep launch refused while probing \(name, privacy: .public) — reporting it as running (a failed spawn is no evidence either way)")
            return true
        }
        guard !result.timedOut, result.terminationStatus != nil else {
            Logger(subsystem: "com.maccrab.detection", category: "es-monitor")
                .error("pgrep did not complete safely while probing \(name, privacy: .public) — reporting it as running")
            return true
        }
        return result.terminationStatus != 1
    }
}
