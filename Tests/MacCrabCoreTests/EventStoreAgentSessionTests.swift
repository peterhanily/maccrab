// EventStoreAgentSessionTests.swift
//
// Wave-3 P1 storage proof: events.ai_tool_session_id was provably always
// NULL in production (no writer). These pin that (1) the column now
// populates from enrichments['ai_tool_session_id'] at insert, and (2)
// eventsForAgentSession(_:) returns exactly the events for that session
// in time order — the durable, session-keyed query the recorder needs.

import Testing
import Foundation
import SQLite3
@testable import MacCrabCore

@Suite("EventStore agent-session column + query")
struct EventStoreAgentSessionTests {

    private static func tempPath() -> String {
        FileManager.default.temporaryDirectory
            .appendingPathComponent("agent-session-\(UUID().uuidString).db").path
    }

    private static func makeEvent(sessionId: String?, at ts: Date) -> Event {
        var enr: [String: String] = ["ai_tool": "claude_code"]
        if let sessionId { enr["ai_tool_session_id"] = sessionId }
        return Event(
            timestamp: ts,
            eventCategory: .process,
            eventType: .start,
            eventAction: "exec",
            process: MacCrabCore.ProcessInfo(
                pid: 4242, ppid: 100, rpid: 4242,
                name: "node", executable: "/usr/local/bin/node",
                commandLine: "node x.js", args: ["node", "x.js"],
                workingDirectory: "/Users/alice/project",
                userId: 501, userName: "alice", groupId: 20,
                startTime: ts, codeSignature: nil, ancestors: [],
                architecture: "arm64", isPlatformBinary: false,
                hashes: nil, session: nil
            ),
            enrichments: enr
        )
    }

    private static func readSessionId(at path: String) -> String? {
        var db: OpaquePointer?
        defer { if let d = db { sqlite3_close(d) } }
        sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY, nil)
        guard let db else { return nil }
        var stmt: OpaquePointer?
        defer { sqlite3_finalize(stmt) }
        guard sqlite3_prepare_v2(db, "SELECT ai_tool_session_id FROM events LIMIT 1", -1, &stmt, nil) == SQLITE_OK,
              sqlite3_step(stmt) == SQLITE_ROW else { return nil }
        if sqlite3_column_type(stmt, 0) == SQLITE_NULL { return nil }
        return String(cString: sqlite3_column_text(stmt, 0))
    }

    @Test("ai_tool_session_id column populates from the enrichment (was always NULL)")
    func columnPopulates() async throws {
        let path = Self.tempPath()
        defer { try? FileManager.default.removeItem(atPath: path) }
        let store = try EventStore(path: path)
        try await store.insert(event: Self.makeEvent(sessionId: "sess-abc", at: Date()))
        #expect(Self.readSessionId(at: path) == "sess-abc")
    }

    @Test("eventsForAgentSession returns only that session's events, in time order")
    func sessionQueryIsolatesAndOrders() async throws {
        let path = Self.tempPath()
        defer { try? FileManager.default.removeItem(atPath: path) }
        let store = try EventStore(path: path)

        let t0 = Date(timeIntervalSince1970: 1_700_000_000)
        try await store.insert(event: Self.makeEvent(sessionId: "S1", at: t0.addingTimeInterval(2)))
        try await store.insert(event: Self.makeEvent(sessionId: "S1", at: t0.addingTimeInterval(1)))
        try await store.insert(event: Self.makeEvent(sessionId: "S2", at: t0.addingTimeInterval(3)))
        try await store.insert(event: Self.makeEvent(sessionId: nil, at: t0.addingTimeInterval(4)))

        let s1 = try await store.eventsForAgentSession("S1")
        #expect(s1.count == 2)
        // Ascending by timestamp.
        #expect(s1.first!.timestamp < s1.last!.timestamp)

        let s2 = try await store.eventsForAgentSession("S2")
        #expect(s2.count == 1)

        // Unstamped + unknown sessions return nothing.
        let none = try await store.eventsForAgentSession("does-not-exist")
        #expect(none.isEmpty)
    }

    @Test("agentSessions aggregates one summary per session, most-recent first")
    func agentSessionsAggregation() async throws {
        let path = Self.tempPath()
        defer { try? FileManager.default.removeItem(atPath: path) }
        let store = try EventStore(path: path)

        let t0 = Date(timeIntervalSince1970: 1_700_000_000)
        // S1: two events; S2: one (more recent); plus an unstamped event.
        try await store.insert(event: Self.makeEvent(sessionId: "S1", at: t0.addingTimeInterval(1)))
        try await store.insert(event: Self.makeEvent(sessionId: "S1", at: t0.addingTimeInterval(2)))
        try await store.insert(event: Self.makeEvent(sessionId: "S2", at: t0.addingTimeInterval(5)))
        try await store.insert(event: Self.makeEvent(sessionId: nil, at: t0.addingTimeInterval(9)))

        let sessions = try await store.agentSessions(limit: 50)
        #expect(sessions.count == 2)                          // unstamped excluded
        #expect(sessions.first?.sessionId == "S2")            // most-recent lastSeen first
        let s1 = sessions.first { $0.sessionId == "S1" }
        #expect(s1?.eventCount == 2)
        #expect(s1?.tool == "claude_code")
        #expect(s1?.firstSeen == t0.addingTimeInterval(1))
        #expect(s1?.lastSeen == t0.addingTimeInterval(2))
    }
}
