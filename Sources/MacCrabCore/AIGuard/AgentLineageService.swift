// AgentLineageService.swift
// MacCrabCore
//
// Agent Data Lineage: weave LLM API calls together with the process,
// file, network, and alert activity for each AI coding-tool session
// into a single chronologically-sorted timeline. The point is to
// answer the question MacCrab is uniquely placed to answer: given an
// agent talking to a cloud model, what did it actually do on the
// machine while that conversation was happening?
//
// This service is a parallel lightweight event log keyed by the AI
// tool's PID. It deliberately does NOT extend the existing
// `AIProcessTracker` struct — the tracker's AISession is a "running
// totals" view, perfect for inline dashboards and ancestor lookups
// but the wrong shape for a timeline. Keeping the two services
// independent means AIProcessTracker can stay minimal and fast, while
// the lineage log carries the ordered-events cost only for callers
// that want a narrative.
//
// The service is in-memory for v1.6.6. Cross-restart durability (SQLite
// persistence of the event log) is scoped for v1.6.7; the in-memory
// ring-buffer protects against unbounded growth in the meantime.

import Foundation
import os.log

// MARK: - AgentEvent

/// A single event in an agent-session timeline. Every event carries a
/// timestamp; the event payload varies by kind.
public struct AgentEvent: Sendable, Hashable {
    public let timestamp: Date
    public let kind: Kind

    public enum Kind: Sendable, Hashable {
        /// The agent made an outbound call to a cloud LLM provider.
        /// `endpoint` is the scheme-less URL path, `bytesUp` is the
        /// request payload size, `bytesDown` the response size.
        case llmCall(provider: String, endpoint: String, bytesUp: Int?, bytesDown: Int?)

        /// The agent spawned a subprocess.
        case processSpawn(basename: String, pid: Int32)

        /// The agent (or a descendant) read a file.
        case fileRead(path: String)

        /// The agent (or a descendant) wrote a file.
        case fileWrite(path: String)

        /// The agent (or a descendant) opened an outbound connection.
        case network(host: String, port: UInt16)

        /// A rule fired on activity inside the agent's subtree.
        case alert(ruleTitle: String, severity: Severity)
    }

    public init(timestamp: Date, kind: Kind) {
        self.timestamp = timestamp
        self.kind = kind
    }
}

// MARK: - AgentSessionSnapshot

public struct AgentSessionSnapshot: Sendable, Hashable {
    public let aiPid: Int32
    public let toolType: AIToolType
    public let projectDir: String?
    public let startTime: Date
    public let events: [AgentEvent]

    public init(aiPid: Int32, toolType: AIToolType, projectDir: String?,
                startTime: Date, events: [AgentEvent]) {
        self.aiPid = aiPid
        self.toolType = toolType
        self.projectDir = projectDir
        self.startTime = startTime
        self.events = events
    }

    /// Number of events in the timeline.
    public var eventCount: Int { events.count }

    /// Count of events matching each kind's category — useful for
    /// dashboard "at a glance" summaries.
    public var kindCounts: (llmCalls: Int, spawns: Int, reads: Int,
                            writes: Int, networks: Int, alerts: Int) {
        var llm = 0, spawn = 0, read = 0, write = 0, net = 0, alert = 0
        for event in events {
            switch event.kind {
            case .llmCall: llm += 1
            case .processSpawn: spawn += 1
            case .fileRead: read += 1
            case .fileWrite: write += 1
            case .network: net += 1
            case .alert: alert += 1
            }
        }
        return (llm, spawn, read, write, net, alert)
    }
}

// MARK: - AgentLineageService

public actor AgentLineageService {
    private let logger = Logger(subsystem: "com.maccrab.aiguard", category: "lineage")

    /// Maximum events stored per session. Ring buffer: once full, the
    /// oldest event is dropped to make room. 10_000 is roughly an hour
    /// of heavy agent activity; more than enough for interactive
    /// investigation, and caps memory at ~1MB / session worst case.
    public static let defaultMaxEventsPerSession = 10_000

    /// Maximum number of sessions retained after they become inactive.
    /// Older sessions are evicted LRU when the limit is reached.
    public static let defaultMaxSessions = 32

    private let maxEventsPerSession: Int
    private let maxSessions: Int

    /// Fixed-capacity circular buffer for events. Replaces the
    /// `[AgentEvent]` + `removeFirst(n)` combo from v1.6.6, which
    /// paid an O(n) array memmove on every append past the cap.
    /// At the 10_000-event cap and a heavy AI workload this was the
    /// dominant cost of the actor. Ring buffer is O(1) append,
    /// O(1) overflow drop, O(N) snapshot (only on dashboard refresh).
    fileprivate struct EventRing {
        private var storage: [AgentEvent?]
        private var head: Int = 0           // next write position
        private var count: Int = 0          // current element count (≤ capacity)
        let capacity: Int

        init(capacity: Int) {
            precondition(capacity > 0, "EventRing capacity must be positive")
            self.capacity = capacity
            self.storage = Array(repeating: nil, count: capacity)
        }

        mutating func append(_ event: AgentEvent) {
            storage[head] = event
            head = (head + 1) % capacity
            if count < capacity { count += 1 }
        }

        /// Ordered snapshot — oldest-first by timestamp. Reads in
        /// insertion order first (ring is insertion-ordered), then
        /// sorts by timestamp. The sort is O(N log N) but this is a
        /// cold path (only called from dashboard refresh / MCP
        /// snapshot export), and it defends against the rare case
        /// where ES events arrive out of order due to collector-
        /// merge or delayed enrichment.
        func snapshotOrdered() -> [AgentEvent] {
            var out: [AgentEvent] = []
            out.reserveCapacity(count)
            // When count < capacity the ring hasn't wrapped yet;
            // indices 0..<count hold the inserted events in order.
            if count < capacity {
                for i in 0..<count {
                    if let e = storage[i] { out.append(e) }
                }
            } else {
                // Wrapped: read capacity-many entries starting from head.
                for offset in 0..<capacity {
                    let idx = (head + offset) % capacity
                    if let e = storage[idx] { out.append(e) }
                }
            }
            return out.sorted { $0.timestamp < $1.timestamp }
        }

        var currentCount: Int { count }
    }

    private struct SessionRecord {
        let aiPid: Int32
        let toolType: AIToolType
        var projectDir: String?
        let startTime: Date
        var events: EventRing
        var lastActivity: Date
    }

    private var sessions: [Int32: SessionRecord] = [:]

    public init(maxEventsPerSession: Int = defaultMaxEventsPerSession,
                maxSessions: Int = defaultMaxSessions) {
        self.maxEventsPerSession = maxEventsPerSession
        self.maxSessions = maxSessions
    }

    // MARK: Session lifecycle

    /// Register an AI-tool process as the root of a new session. If a
    /// session for the PID already exists, this is a no-op — the tracker
    /// already knew about it.
    public func startSession(aiPid: Int32, toolType: AIToolType,
                             projectDir: String?, startTime: Date = Date()) {
        if sessions[aiPid] != nil { return }
        evictIfNecessary()
        sessions[aiPid] = SessionRecord(
            aiPid: aiPid, toolType: toolType,
            projectDir: projectDir,
            startTime: startTime,
            events: EventRing(capacity: maxEventsPerSession),
            lastActivity: startTime
        )
    }

    public func endSession(aiPid: Int32) {
        sessions[aiPid] = nil
    }

    // MARK: Event recording

    /// Append an event to a session's timeline. If the PID isn't a
    /// known session, this is silently dropped — the EventLoop may
    /// route events before a corresponding `startSession` lands.
    ///
    /// v1.6.9: backed by `EventRing` — O(1) append, O(1) drop when at
    /// capacity. Previously used `[AgentEvent]` + `removeFirst(n)`
    /// which memmoved the entire tail array every time we overflowed
    /// the cap.
    public func record(aiPid: Int32, event: AgentEvent) {
        guard var record = sessions[aiPid] else { return }
        record.events.append(event)
        record.lastActivity = event.timestamp
        sessions[aiPid] = record
    }

    /// Bulk-record helper for when the caller already knows the AI pid.
    public func record(aiPid: Int32, kind: AgentEvent.Kind, timestamp: Date = Date()) {
        record(aiPid: aiPid, event: AgentEvent(timestamp: timestamp, kind: kind))
    }

    // MARK: Queries

    public func snapshot(aiPid: Int32) -> AgentSessionSnapshot? {
        guard let record = sessions[aiPid] else { return nil }
        return AgentSessionSnapshot(
            aiPid: record.aiPid, toolType: record.toolType,
            projectDir: record.projectDir, startTime: record.startTime,
            events: record.events.snapshotOrdered()
        )
    }

    /// All sessions, most-recently-active first.
    public func allSessions() -> [AgentSessionSnapshot] {
        sessions.values
            .sorted { $0.lastActivity > $1.lastActivity }
            .map { record in
                AgentSessionSnapshot(
                    aiPid: record.aiPid, toolType: record.toolType,
                    projectDir: record.projectDir, startTime: record.startTime,
                    events: record.events.snapshotOrdered()
                )
            }
    }

    /// Events from a given session that intersect a time window. The
    /// underlying ring is already insertion-ordered; `snapshotOrdered`
    /// returns oldest-first, so we just filter.
    public func events(aiPid: Int32, since start: Date? = nil, until end: Date? = nil) -> [AgentEvent] {
        guard let record = sessions[aiPid] else { return [] }
        let ordered = record.events.snapshotOrdered()
        return ordered.filter { event in
            if let start, event.timestamp < start { return false }
            if let end, event.timestamp > end { return false }
            return true
        }
    }

    // MARK: Bookkeeping

    private func evictIfNecessary() {
        guard sessions.count >= maxSessions else { return }
        if let oldest = sessions.values.sorted(by: { $0.lastActivity < $1.lastActivity }).first {
            sessions[oldest.aiPid] = nil
            logger.info("Evicted inactive AI session \(oldest.aiPid) to stay under max-sessions cap")
        }
    }
}
