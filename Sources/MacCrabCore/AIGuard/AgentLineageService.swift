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
public struct AgentEvent: Sendable, Hashable, Codable {
    public let timestamp: Date
    public let kind: Kind

    public enum Kind: Sendable, Hashable, Codable {
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

public struct AgentSessionSnapshot: Sendable, Hashable, Codable {
    public let aiPid: Int32
    public let toolType: AIToolType
    public let projectDir: String?
    public let startTime: Date
    public let events: [AgentEvent]
    /// Wall-clock of the most recent event in this snapshot. Used by
    /// the dashboard to mark "stale" sessions and sort the timeline
    /// view by recency without walking the events array.
    public let lastActivity: Date

    public init(aiPid: Int32, toolType: AIToolType, projectDir: String?,
                startTime: Date, events: [AgentEvent],
                lastActivity: Date? = nil) {
        self.aiPid = aiPid
        self.toolType = toolType
        self.projectDir = projectDir
        self.startTime = startTime
        self.events = events
        self.lastActivity = lastActivity
            ?? events.last?.timestamp
            ?? startTime
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
    /// oldest event is dropped to make room. v1.6.22 cut from 10_000 →
    /// 2_000 — at 32 sessions × 10K events × ~300 B/event the worst-case
    /// resident hit was ~96 MB. 2_000 covers ~12 min of heavy agent
    /// activity per session (still enough for the timeline view to show
    /// a meaningful window) and caps the worst case at ~19 MB across
    /// all 32 sessions.
    public static let defaultMaxEventsPerSession = 2_000

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

    /// Snapshot publication is serialized but its JSON encoding and disk I/O
    /// run outside this actor. The previous synchronous implementation kept
    /// the actor occupied for the entire encode/write, so `record` and
    /// `endSession` could stall behind a slow disk. Its `snapshotWriteInFlight`
    /// guard could not help: a synchronous actor method cannot be re-entered
    /// while the write is running, so the guard was never observed as true.
    ///
    /// At most one immutable snapshot is in flight and one latest snapshot is
    /// pending. A newer pending generation supersedes the older pending copy;
    /// this bounds retained snapshot memory while ensuring the writer catches
    /// up to the newest state after a slow publication completes. The original
    /// caller remains joined until the in-flight and pending generations drain,
    /// so daemon timer shutdown still owns every publication task.
    private let snapshotWriter: CoalescingSnapshotWriter<LineageSnapshot>

    public struct SnapshotWriteTelemetry: Sendable, Equatable {
        public let offered: UInt64
        public let started: UInt64
        public let completed: UInt64
        public let failed: UInt64
        public let superseded: UInt64
        public let inFlight: Int
        public let pending: Int

        public var conserved: Bool {
            offered == completed
                &+ failed
                &+ superseded
                &+ UInt64(inFlight)
                &+ UInt64(pending)
        }
    }

    public init(maxEventsPerSession: Int = defaultMaxEventsPerSession,
                maxSessions: Int = defaultMaxSessions) {
        self.maxEventsPerSession = maxEventsPerSession
        self.maxSessions = maxSessions
        self.snapshotWriter = CoalescingSnapshotWriter(
            category: "agent-lineage-snapshot",
            persistence: Self.persistSnapshot
        )
    }

    init(
        maxEventsPerSession: Int = defaultMaxEventsPerSession,
        maxSessions: Int = defaultMaxSessions,
        snapshotPersistence: @escaping @Sendable (LineageSnapshot, String) -> String?
    ) {
        self.maxEventsPerSession = maxEventsPerSession
        self.maxSessions = maxSessions
        self.snapshotWriter = CoalescingSnapshotWriter(
            category: "agent-lineage-snapshot-test",
            persistence: snapshotPersistence
        )
    }

    /// Canonical file-path materialisation contract for the agent timeline.
    ///
    /// PromptIntentBridge is the security consumer of lineage file paths: it
    /// reads recent `.fileRead` context and inspects that bounded text corpus.
    /// FileInjectionScanner already owns the exact completed-text event
    /// contract, so lineage reuses it and creates no additional callback
    /// demand. Early CREATE/WRITE callbacks, binary/PDF/Office files, and raw
    /// temp/cache churn do not justify path-bearing timeline entries; fixed
    /// callback telemetry can count them without retaining private paths.
    /// Credential-shaped paths are never persisted here.
    public nonisolated static func materializedFileEventKind(
        path: String,
        eventAction: String
    ) -> AgentEvent.Kind? {
        guard !CredentialFence.isPrivateAgentLineagePath(path) else {
            return nil
        }
        guard FileInjectionScanner.isEligible(
            path: path,
            eventAction: eventAction
        ) else {
            return nil
        }
        switch eventAction.lowercased() {
        case "open":
            return .fileRead(path: path)
        case "close_modified":
            return .fileWrite(path: path)
        default:
            // Kept defensive even though isEligible currently enforces the
            // same closed action set.
            return nil
        }
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

    /// v1.12.0 RC4 (Int-R4-N2): `endSession` has no production
    /// caller today — EventLoop's process-EXIT path doesn't invoke
    /// it. Cleanup is currently handled implicitly by `startSession`'s
    /// `evictIfNecessary` (32-session LRU cap), keeping the in-memory
    /// footprint bounded (~19MB worst-case at 2K events/session).
    /// Stale snapshots are a minor freshness concern for
    /// PromptIntentBridge — its 300s window naturally bounds the
    /// data it considers — but a future v1.12.x patch should wire
    /// EventLoop.swift's process-EXIT handler to call this so we
    /// release session memory proactively instead of relying on LRU
    /// eviction under churn.
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
                    events: record.events.snapshotOrdered(),
                    lastActivity: record.lastActivity
                )
            }
    }

    // MARK: - Cross-process snapshot (sysext → app)

    /// On-disk snapshot wrapper. The dashboard's `AIActivityView`
    /// reads this file from `<supportDir>/agent_lineage.json` to render
    /// the chronological timeline. Daemon writes through
    /// `writeSnapshot(to:)`; app reads through
    /// `AgentLineageService.readSnapshot(at:)`.
    public struct LineageSnapshot: Sendable, Codable {
        public let writtenAt: Date
        public let sessions: [AgentSessionSnapshot]
        public init(writtenAt: Date, sessions: [AgentSessionSnapshot]) {
            self.writtenAt = writtenAt
            self.sessions = sessions
        }
    }

    /// Publish an immutable copy of the live state. Snapshot assembly is
    /// bounded by the session/event caps and occurs on this actor; JSON encoding
    /// and descriptor-safe atomic replacement execute in a detached child and
    /// therefore cannot block event recording. Concurrent timer calls retain
    /// only their newest pending generation.
    public func writeSnapshot(to path: String) async {
        let snapshot = LineageSnapshot(writtenAt: Date(), sessions: allSessions())
        await snapshotWriter.publish(snapshot, to: path)
    }

    /// Fixed-cardinality conservation telemetry for heartbeat/UI plumbing.
    public func snapshotWriteTelemetry() async -> SnapshotWriteTelemetry {
        let telemetry = await snapshotWriter.telemetry()
        return SnapshotWriteTelemetry(
            offered: telemetry.offered,
            started: telemetry.started,
            completed: telemetry.completed,
            failed: telemetry.failed,
            superseded: telemetry.superseded,
            inFlight: telemetry.inFlight,
            pending: telemetry.pending
        )
    }

    /// Encode and atomically replace outside the lineage actor. The secure
    /// writer refuses symlink/hard-link/foreign-owned destinations and fsyncs
    /// complete bytes before publication. The admin group keeps the
    /// user-context dashboard readable without making private lineage data
    /// world-readable.
    @Sendable
    private nonisolated static func persistSnapshot(
        _ snapshot: LineageSnapshot,
        to path: String
    ) -> String? {
        do {
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
            let data = try encoder.encode(snapshot)
            try SecureFileIO.atomicReplace(at: path, data: data, mode: 0o640)
            try? FileManager.default.setAttributes(
                [.posixPermissions: 0o640, .groupOwnerAccountID: 80],
                ofItemAtPath: path
            )
            return nil
        } catch {
            return String(error.localizedDescription.prefix(512))
        }
    }

    /// Read a daemon-written snapshot. Returns nil on missing or
    /// malformed file — callers fall back to "no sessions" UI state.
    public static func readSnapshot(at path: String) -> LineageSnapshot? {
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)) else { return nil }
        return try? JSONDecoder().decode(LineageSnapshot.self, from: data)
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
        // AI-09: evict EMPTY sessions first. Pure-LRU eviction discarded the
        // sessions that actually held timelines — a session with no recorded
        // events has a `lastActivity` frozen at its creation time, so under any
        // churn of short-lived agent roots the zero-event ghosts looked "most
        // recent" only briefly and then crowded out the long-running session
        // the user is trying to inspect. An eventless session carries no
        // information by definition, so it is always the correct victim.
        // Defence in depth for the fork fix in EventLoop, which removes the
        // dominant ghost SOURCE; this makes the cap fail gracefully regardless.
        let victim = sessions.values
            .sorted { lhs, rhs in
                let lhsEmpty = lhs.events.snapshotOrdered().isEmpty
                let rhsEmpty = rhs.events.snapshotOrdered().isEmpty
                if lhsEmpty != rhsEmpty { return lhsEmpty }
                return lhs.lastActivity < rhs.lastActivity
            }
            .first
        if let victim {
            sessions[victim.aiPid] = nil
            logger.info("Evicted inactive AI session \(victim.aiPid) to stay under max-sessions cap")
        }
    }
}
