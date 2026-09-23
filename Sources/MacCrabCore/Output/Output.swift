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

// MARK: - Batching helpers

/// NDJSON batch buffer shared by the batching sinks (S3, SFTP). Records are
/// appended one newline-terminated line at a time; a flush takes the whole
/// buffer, and a failed flush hands it back so the next flush retries it. The
/// buffer is bounded in both bytes and records: whenever either cap is
/// exceeded the OLDEST records are dropped first, and the caller is told how
/// many so it can account for them in `OutputStats.dropped`.
struct OutputBatchBuffer: Sendable {
    private(set) var data = Data()
    private(set) var count = 0
    let maxRetainedBytes: Int
    let maxRetainedRecords: Int

    init(maxRetainedBytes: Int, maxRetainedRecords: Int) {
        self.maxRetainedBytes = max(1, maxRetainedBytes)
        self.maxRetainedRecords = max(1, maxRetainedRecords)
    }

    var isEmpty: Bool { data.isEmpty }

    /// Append one newline-terminated record. Returns the number of oldest
    /// records dropped to stay within the caps (normally zero).
    @discardableResult
    mutating func append(line: Data) -> Int {
        data.append(line)
        count += 1
        return enforceCaps()
    }

    /// Move the buffered batch out, leaving the buffer empty.
    mutating func take() -> (payload: Data, count: Int) {
        let taken = (data, count)
        data.removeAll(keepingCapacity: true)
        count = 0
        return taken
    }

    /// Put a batch that failed to deliver back in FRONT of anything appended
    /// since it was taken, so record order is preserved for the retry, then
    /// enforce the caps oldest-first. Returns the number of records dropped.
    @discardableResult
    mutating func retain(payload: Data, count retainedCount: Int) -> Int {
        guard !payload.isEmpty, retainedCount > 0 else { return 0 }
        var merged = payload
        merged.append(data)
        data = merged
        count += retainedCount
        return enforceCaps()
    }

    private mutating func enforceCaps() -> Int {
        var dropped = 0
        var cut = data.startIndex
        var remainingCount = count
        var remainingBytes = data.count
        while remainingCount > 0,
              remainingCount > maxRetainedRecords || remainingBytes > maxRetainedBytes {
            guard let newline = data[cut...].firstIndex(of: 0x0A) else {
                // Unterminated tail: the only way to get under the cap is to
                // drop everything that is left.
                dropped += remainingCount
                remainingCount = 0
                cut = data.endIndex
                break
            }
            let next = data.index(after: newline)
            remainingBytes -= data.distance(from: cut, to: next)
            cut = next
            remainingCount -= 1
            dropped += 1
        }
        if cut > data.startIndex {
            data.removeSubrange(data.startIndex..<cut)
            count = remainingCount
        }
        return dropped
    }
}

/// Exponential retry gate for a batching sink's flush, mirroring the
/// `pow(2, attempt) * 0.5` backoff `StreamOutput` uses between its in-request
/// retries. A failed flush retains its batch; the next flush is allowed only
/// once the backoff has elapsed, so a sink that is down is not hammered by
/// every size-triggered flush. Capped at five minutes, the default flush
/// cadence, so a recovered sink is never ignored for longer than one tick.
struct OutputRetryBackoff: Sendable {
    private(set) var consecutiveFailures = 0
    private(set) var nextAttemptAt: Date? = nil
    static let maximumDelaySeconds: TimeInterval = 300

    func mayAttempt(now: Date) -> Bool {
        guard let nextAttemptAt else { return true }
        return now >= nextAttemptAt
    }

    mutating func recordFailure(now: Date) {
        consecutiveFailures += 1
        let delay = min(
            pow(2.0, Double(consecutiveFailures)) * 0.5,
            Self.maximumDelaySeconds
        )
        nextAttemptAt = now.addingTimeInterval(delay)
    }

    mutating func recordSuccess() {
        consecutiveFailures = 0
        nextAttemptAt = nil
    }
}
