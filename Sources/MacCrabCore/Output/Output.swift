// Output.swift
// MacCrabCore
//
// Shared protocol every alert output conforms to. Gives the daemon event
// loop a single way to fan out alerts to every configured sink (webhook,
// syslog, file, Splunk HEC, Elasticsearch, S3, SFTP) without hardcoding
// an if-let ladder per sink.
//
// Fire-and-forget by design — every Output is an actor so dispatch is
// non-blocking and each sink handles its own retry + buffering. A
// failing sink never stalls the detection pipeline.

import Foundation

// MARK: - OutputStats

/// Observability counters surfaced to the dashboard + health endpoints.
public struct OutputStats: Sendable, Hashable, Codable {
    public var sent: Int = 0
    public var failed: Int = 0
    public var dropped: Int = 0           // queue overflow, too-large payload, etc.
    public var lastError: String? = nil
    public var lastSentAt: Date? = nil

    public init(
        sent: Int = 0, failed: Int = 0, dropped: Int = 0,
        lastError: String? = nil, lastSentAt: Date? = nil
    ) {
        self.sent = sent
        self.failed = failed
        self.dropped = dropped
        self.lastError = lastError
        self.lastSentAt = lastSentAt
    }
}

// MARK: - OutputHealth

/// Coarse health signal for the dashboard's Integrations view. Green when
/// the last send succeeded; yellow when it failed but we're retrying;
/// red when retries are exhausted or the sink can't reach its target.
public enum OutputHealth: String, Sendable, Codable {
    case healthy
    case degraded
    case failing
    case unknown
}

// MARK: - Output protocol

public protocol Output: Actor {
    /// Short, stable identifier — "webhook", "file", "splunk_hec", etc.
    /// Used in config files, logs, and the dashboard.
    nonisolated var name: String { get }

    /// Deliver one alert (and, when available, its originating event).
    /// Implementations MUST NOT block the caller — enqueue + return, do
    /// network / disk I/O on the actor's own executor.
    func send(alert: Alert, event: Event?) async

    /// Optional synchronous flush barrier. Fire-and-forget outputs can
    /// no-op. Batching outputs (file with a write buffer, HTTP bulk with
    /// a pending batch) use this to drain on daemon shutdown.
    func flush() async

    /// Snapshot of per-output observability counters.
    func outputStats() async -> OutputStats

    /// Coarse health signal. Default implementation derives from stats.
    func health() async -> OutputHealth
}

// MARK: - Default impls

extension Output {
    /// Default health: healthy unless the latest send failed or no send
    /// has happened yet.
    public func health() async -> OutputHealth {
        let s = await outputStats()
        if s.sent == 0 && s.failed == 0 {
            return .unknown
        }
        if s.failed > 0 && s.sent == 0 {
            return .failing
        }
        // More than 10% failure rate in recent history → degraded.
        let total = s.sent + s.failed
        if total > 0 && Double(s.failed) / Double(total) > 0.1 {
            return .degraded
        }
        return .healthy
    }

    /// Default flush is a no-op (fire-and-forget).
    public func flush() async { }
}
