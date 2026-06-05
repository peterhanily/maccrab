// SourceRestartPolicy.swift
// v1.18 — restart/backoff/escalation policy for collector stream loops
// (DaemonState.mergedEventStream).
//
// Before v1.18 each source re-iterated its AsyncStream after a FIXED 2s sleep.
// When a stream ends PERMANENTLY (ES client invalidated, eslogger subprocess
// gone) re-iterating returns immediately, so the loop hot-spun at 2s forever —
// logging a warning, never backing off, never escalating — while the heartbeat
// kept writing green. The host could go silently blind on its highest-fidelity
// sensor with no operator signal. This makes the decision logic a pure, testable
// state machine: exponential backoff (stop hot-spinning) + a one-shot escalation
// to CRITICAL once a source has stayed down across repeated empty re-attaches.

import Foundation

/// Backoff schedule + down-threshold for a single collector restart loop.
public struct SourceRestartPolicy: Sendable {
    public let baseDelay: TimeInterval
    public let maxDelay: TimeInterval
    /// Consecutive EMPTY re-attaches (stream re-ended yielding no event) before
    /// the source is declared down. A re-attach that yields ≥1 event resets it.
    public let downThreshold: Int

    public init(baseDelay: TimeInterval = 2, maxDelay: TimeInterval = 60, downThreshold: Int = 5) {
        self.baseDelay = baseDelay
        self.maxDelay = maxDelay
        self.downThreshold = max(1, downThreshold)
    }

    /// Backoff delay after `n` consecutive empty re-attaches, capped at maxDelay.
    /// A productive attach (n == 0) returns baseDelay.
    public func delay(consecutiveEmpty n: Int) -> TimeInterval {
        guard n > 0 else { return baseDelay }
        let scaled = baseDelay * pow(2, Double(min(n - 1, 16)))
        return min(scaled, maxDelay)
    }

    public func isDown(consecutiveEmpty n: Int) -> Bool { n >= downThreshold }
}

/// Per-source restart state machine. `record(produced:)` is called once per
/// stream re-attach with whether that attach yielded any events, and returns
/// what the loop should do next.
public struct SourceRestartState: Sendable {
    public enum Outcome: Equatable, Sendable {
        case retry(delay: TimeInterval)
        /// First time the source crosses the down-threshold — escalate to CRITICAL.
        case escalate(delay: TimeInterval)
        /// Produced events again after having previously escalated — recovered.
        case recovered(delay: TimeInterval)
    }

    public let policy: SourceRestartPolicy
    public private(set) var consecutiveEmpty = 0
    public private(set) var escalated = false

    public init(policy: SourceRestartPolicy = SourceRestartPolicy()) { self.policy = policy }

    public mutating func record(produced: Bool) -> Outcome {
        if produced {
            consecutiveEmpty = 0
            if escalated {
                escalated = false
                return .recovered(delay: policy.delay(consecutiveEmpty: 0))
            }
            return .retry(delay: policy.delay(consecutiveEmpty: 0))
        }
        consecutiveEmpty += 1
        let delay = policy.delay(consecutiveEmpty: consecutiveEmpty)
        if policy.isDown(consecutiveEmpty: consecutiveEmpty) && !escalated {
            escalated = true
            return .escalate(delay: delay)
        }
        return .retry(delay: delay)
    }
}
