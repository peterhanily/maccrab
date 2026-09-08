import Foundation

/// Native ES callback progress and the existing coverage probe are independent
/// of downstream normalized-event counts. No probe is scheduled by this model.
public final class ESDeliveryHealth: @unchecked Sendable {
    public static let canaryMinimumIntervalSeconds: Double = 300
    public static let canaryMaximumIntervalSeconds: Double = 900
    public static let canarySettleSeconds: UInt64 = 20
    public static let canaryDBRecheckAttempts = 3
    public static let canaryDBRecheckSeconds: UInt64 = 5
    /// One maximum scheduled interval plus the existing probe settlement path.
    /// This is a liveness deadline, not a guarantee of database query duration.
    public static let maximumProofAgeSeconds: Double = canaryMaximumIntervalSeconds
        + Double(canarySettleSeconds)
        + Double(canaryDBRecheckAttempts) * Double(canaryDBRecheckSeconds)

    public enum CanaryOutcome: String, Codable, Sendable, Hashable {
        case healthy, kernelGap, ingestHandoffGap, evictionGap, storeQueryUnknown
        case spawnFailed, cancelled
    }

    public struct Snapshot: Codable, Sendable, Hashable {
        public let state: CollectorHealthState
        public let reason: String
        public let callbackAgeSeconds: Double?
        public let canaryAgeSeconds: Double?
        public let canaryOutcome: CanaryOutcome?
        /// Cumulative for this one-shot native collector instance. Production
        /// creates its replacement only in a new engine process/boot identity.
        public let canaryChecksTotal: UInt64
        public let canaryFailuresTotal: UInt64
        public let lastError: String?
    }

    private let lock = NSLock()
    private let monotonicNow: @Sendable () -> UInt64
    private var startedAt: UInt64?
    private var stopped = false
    private var generation: UInt64 = 0
    private var activeCanary: UInt64?
    private var lastCanaryStartedAt: UInt64?
    private var lastCanaryCompletedAt: UInt64?
    private var lastOutcome: CanaryOutcome?
    private var checks: UInt64 = 0
    private var failures: UInt64 = 0
    private var lastError: String?

    init(monotonicNow: @escaping @Sendable () -> UInt64 = { DispatchTime.now().uptimeNanoseconds }) {
        self.monotonicNow = monotonicNow
    }

    func started() {
        lock.lock(); defer { lock.unlock() }
        guard startedAt == nil, !stopped else { return }
        startedAt = monotonicNow()
    }

    func stop() {
        lock.lock(); defer { lock.unlock() }
        stopped = true
        activeCanary = nil
    }

    public func beginCanary() -> UInt64? {
        lock.lock(); defer { lock.unlock() }
        guard startedAt != nil, !stopped else { return nil }
        generation &+= 1
        activeCanary = generation
        lastCanaryStartedAt = monotonicNow()
        return generation
    }

    public func finishCanary(_ token: UInt64, outcome: CanaryOutcome) {
        lock.lock(); defer { lock.unlock() }
        guard !stopped, activeCanary == token else { return }
        activeCanary = nil
        lastCanaryCompletedAt = monotonicNow()
        let effectiveOutcome: CanaryOutcome = Task.isCancelled ? .cancelled : outcome
        lastOutcome = effectiveOutcome
        checks = checks == .max ? .max : checks + 1
        if effectiveOutcome != .healthy {
            failures = failures == .max ? .max : failures + 1
            lastError = "coverage canary: \(effectiveOutcome.rawValue)"
        }
    }

    /// A missed storage deadline remains a recorded failure while the same
    /// probe waits in the ordinary pipeline. Only the latest probe may be
    /// reconciled, within the existing proof-age horizon from its start.
    /// Starting another probe or stopping the collector invalidates this work.
    public func canReconcileStoredCanary(_ token: UInt64) -> Bool {
        lock.lock(); defer { lock.unlock() }
        return canReconcileStoredCanaryLocked(token)
    }

    /// Called only after the callback-seen probe obtains a positive FTS proof.
    /// Rechecking is not a new probe: preserve both check and failure history.
    @discardableResult
    public func reconcileStoredCanary(_ token: UInt64) -> Bool {
        lock.lock(); defer { lock.unlock() }
        guard !Task.isCancelled, canReconcileStoredCanaryLocked(token) else { return false }
        lastOutcome = .healthy
        lastCanaryCompletedAt = monotonicNow()
        return true
    }

    private func canReconcileStoredCanaryLocked(_ token: UInt64) -> Bool {
        guard !stopped, generation == token, activeCanary == nil,
              lastOutcome == .storeQueryUnknown || lastOutcome == .evictionGap,
              let started = lastCanaryStartedAt else { return false }
        let now = monotonicNow()
        guard now >= started else { return false }
        return Double(now - started) / 1_000_000_000 <= Self.maximumProofAgeSeconds
    }

    public func snapshot(lastCallbackUptimeNanoseconds: UInt64?) -> Snapshot {
        lock.lock(); defer { lock.unlock() }
        let instant = monotonicNow()
        func age(_ time: UInt64?) -> Double? {
            guard let time, time <= instant else { return nil }
            return Double(instant - time) / 1_000_000_000
        }
        let callbackAge = age(lastCallbackUptimeNanoseconds)
        let canaryAge = age(lastCanaryCompletedAt ?? startedAt)
        let state: CollectorHealthState
        let reason: String
        if stopped {
            state = .failed; reason = "native ES client stopped"
        } else if startedAt == nil {
            state = .starting; reason = "native ES client not started"
        } else if let lastOutcome, lastOutcome != .healthy {
            state = .failed; reason = "coverage canary: \(lastOutcome.rawValue)"
        } else if canaryAge == nil || canaryAge! > Self.maximumProofAgeSeconds {
            state = .stalled; reason = "coverage canary proof is overdue or unavailable"
        } else if lastCallbackUptimeNanoseconds == nil {
            state = .starting; reason = "native ES client awaiting first callback"
        } else if callbackAge == nil || callbackAge! > Self.maximumProofAgeSeconds {
            state = .stalled; reason = "native ES callbacks are overdue or unavailable"
        } else {
            state = .healthy; reason = "native callbacks active"
        }
        return Snapshot(state: state, reason: reason, callbackAgeSeconds: callbackAge,
                        canaryAgeSeconds: canaryAge, canaryOutcome: lastOutcome,
                        canaryChecksTotal: checks, canaryFailuresTotal: failures,
                        lastError: lastError)
    }
}
