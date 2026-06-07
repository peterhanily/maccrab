// AgentSessionRegistry — the durable-session-id substrate for the
// Wave-3 agent-session recorder (Phase 1 spike).
//
// PROBLEM (today): an "agent session" is keyed only by live OS PID
// (AgentLineageService.sessions: [Int32: …]). No id survives the
// process, so kernel events / alerts / mutations can't be correlated
// to a session after the PID dies or recycles, and events.ai_tool_
// session_id is provably always NULL in production (no writer).
//
// THIS: mint a durable UUID session id the first time an AI-tool root
// process is seen, keyed by an anti-recycle identity (pid + startTime
// + executable pathHash), and resolve EVERY correlated event — the AI
// tool's OWN events AND its descendants (via the ancestor walk) — to
// that id, so it can be stamped into events.ai_tool_session_id before
// insert. A bounded grace window keeps a session resolvable for a
// short time after the root exits, so descendant events that outlive
// the parent (the common case) still correlate instead of dropping.
//
// The four coverage cases the recorder hinges on (AgentSessionRegistry
// Tests pins all four): (a) a direct AI child, (b) a deep descendant,
// (c) the AI tool's OWN file/net event, (d) a descendant arriving
// after the root has exited.

import Foundation

public actor AgentSessionRegistry {

    private struct Entry {
        let sessionId: String
        let pathHash: UInt64
        let toolRaw: String
        let startTime: Date
        var lastSeen: Date
        var endedAt: Date?
    }

    /// Live + recently-ended sessions, keyed by the root AI-tool PID.
    /// pathHash + startTime on the entry guard against PID recycle.
    private var byPid: [Int32: Entry] = [:]

    /// How long a session stays resolvable after its root process exits,
    /// so descendant events that outlive the parent still correlate.
    private let graceWindow: TimeInterval

    /// Cap on retained sessions (live + in-grace); oldest-by-lastSeen
    /// evicted past this.
    private let maxSessions: Int

    /// Tolerance when comparing a root's startTime to a retained entry's
    /// — ES timestamps for the same exec can wobble sub-second.
    private static let startTimeTolerance: TimeInterval = 2

    public init(graceWindow: TimeInterval = 300, maxSessions: Int = 64) {
        self.graceWindow = graceWindow
        self.maxSessions = maxSessions
    }

    /// Mint-or-get the durable session id for an AI-tool ROOT process
    /// (the event subject IS the AI tool). Reuses the existing id when
    /// the same root is seen again; mints a fresh id when the PID has
    /// been recycled into a different process (pathHash or startTime
    /// disagree) or the prior session aged out of grace.
    @discardableResult
    public func session(rootPid: Int32, pathHash: UInt64, startTime: Date,
                        tool: String, now: Date = Date()) -> String {
        if var e = byPid[rootPid],
           e.pathHash == pathHash,
           abs(e.startTime.timeIntervalSince(startTime)) <= Self.startTimeTolerance,
           !isExpired(e, now: now) {
            e.lastSeen = now
            e.endedAt = nil           // a fresh event from the root revives it
            byPid[rootPid] = e
            return e.sessionId
        }
        let id = UUID().uuidString.lowercased()
        byPid[rootPid] = Entry(sessionId: id, pathHash: pathHash, toolRaw: tool,
                               startTime: startTime, lastSeen: now, endedAt: nil)
        evictIfNeeded(now: now)
        return id
    }

    /// Resolve the session id for a DESCENDANT event by its nearest
    /// AI-tool ancestor's pid. Ancestors carry no startTime, so the
    /// recycle guard is pathHash-only (nil = skip the check). Returns
    /// nil if no live/in-grace session matches.
    public func sessionForRoot(pid: Int32, pathHash: UInt64?, now: Date = Date()) -> String? {
        guard var e = byPid[pid] else { return nil }
        if let ph = pathHash, e.pathHash != ph { return nil }   // pid recycled into a different exe
        if isExpired(e, now: now) { return nil }
        e.lastSeen = now
        byPid[pid] = e
        return e.sessionId
    }

    /// Mark a root's session ended (e.g. on the AI-tool process EXIT).
    /// The entry survives for `graceWindow` so late descendant events
    /// still resolve.
    public func end(rootPid: Int32, now: Date = Date()) {
        if var e = byPid[rootPid] {
            e.endedAt = now
            byPid[rootPid] = e
        }
    }

    /// Test/inspection: number of retained sessions.
    public func count() -> Int { byPid.count }

    // MARK: - internals

    private func isExpired(_ e: Entry, now: Date) -> Bool {
        guard let ended = e.endedAt else { return false }
        return now.timeIntervalSince(ended) > graceWindow
    }

    private func evictIfNeeded(now: Date) {
        // Drop entries already past grace, then LRU-trim to the cap.
        byPid = byPid.filter { !isExpired($0.value, now: now) }
        guard byPid.count > maxSessions else { return }
        let victims = byPid.sorted { $0.value.lastSeen < $1.value.lastSeen }
            .prefix(byPid.count - maxSessions)
            .map { $0.key }
        for pid in victims { byPid.removeValue(forKey: pid) }
    }
}
