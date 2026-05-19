// AgentTraceColumnPersistenceTests.swift
// v1.9 audit B1 regression pin — events.db schema v4 added 5 agent_*
// columns but the INSERT statement was never updated, so every event
// silently wrote NULL into them. Pin the round-trip from
// `event.enrichments` (where TraceCorrelator.flatten writes) → SQL
// columns (where rules + the partial index expect to read).

import Testing
import Foundation
import CSQLCipher
@testable import MacCrabCore

@Suite("EventStore: agent_* column projection (v1.9 audit B1 regression)")
struct AgentTraceColumnPersistenceTests {

    private static func tempPath() -> String {
        FileManager.default.temporaryDirectory
            .appendingPathComponent("agent-cols-\(UUID().uuidString).db").path
    }

    private static func sampleProcess() -> MacCrabCore.ProcessInfo {
        MacCrabCore.ProcessInfo(
            pid: 12345, ppid: 1, rpid: 0,
            name: "claude", executable: "/usr/local/bin/claude",
            commandLine: "claude -p hi", args: ["claude"], workingDirectory: "/",
            userId: 501, userName: "u", groupId: 20,
            startTime: Date(), codeSignature: nil, ancestors: [],
            architecture: nil, isPlatformBinary: false
        )
    }

    @Test("Event with agent enrichments persists into v4 columns")
    func enrichmentsLandInColumns() async throws {
        let path = Self.tempPath()
        defer { try? FileManager.default.removeItem(atPath: path) }
        let store = try EventStore(path: path)

        var event = Event(
            eventCategory: .process,
            eventType: .start,
            eventAction: "exec",
            process: Self.sampleProcess()
        )
        event.enrichments[TraceCorrelator.EnrichmentKey.traceId]      = "4bf92f3577b34da6a3ce929d0e0e4736"
        event.enrichments[TraceCorrelator.EnrichmentKey.spanId]       = "00f067aa0ba902b7"
        event.enrichments[TraceCorrelator.EnrichmentKey.agentTool]    = "claude_code"
        event.enrichments[TraceCorrelator.EnrichmentKey.confidence]   = "traceparent"
        event.enrichments[TraceCorrelator.EnrichmentKey.evidenceJson] = #"{"schemaVersion":1}"#

        try await store.insert(event: event)

        // Open a fresh raw handle and read the columns directly.
        var db: OpaquePointer?
        defer { if let d = db { sqlite3_close(d) } }
        guard sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY, nil) == SQLITE_OK else {
            Issue.record("open db read-only failed")
            return
        }
        let sql = """
            SELECT agent_trace_id, agent_span_id, agent_tool,
                   machine_agent_confidence, agent_evidence_json
            FROM events
            """
        var stmt: OpaquePointer?
        defer { if let s = stmt { sqlite3_finalize(s) } }
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK,
              sqlite3_step(stmt) == SQLITE_ROW else {
            Issue.record("expected one row")
            return
        }
        let traceId = String(cString: sqlite3_column_text(stmt, 0))
        let spanId = String(cString: sqlite3_column_text(stmt, 1))
        let agentTool = String(cString: sqlite3_column_text(stmt, 2))
        let confidence = String(cString: sqlite3_column_text(stmt, 3))
        let evidence = String(cString: sqlite3_column_text(stmt, 4))
        #expect(traceId == "4bf92f3577b34da6a3ce929d0e0e4736")
        #expect(spanId == "00f067aa0ba902b7")
        #expect(agentTool == "claude_code")
        #expect(confidence == "traceparent")
        #expect(evidence.contains("schemaVersion"))
    }

    @Test("Event without agent enrichments writes NULL into columns")
    func nullColumnsForNonAgentEvent() async throws {
        let path = Self.tempPath()
        defer { try? FileManager.default.removeItem(atPath: path) }
        let store = try EventStore(path: path)
        let event = Event(
            eventCategory: .process,
            eventType: .start,
            eventAction: "exec",
            process: Self.sampleProcess()
        )
        try await store.insert(event: event)

        var db: OpaquePointer?
        defer { if let d = db { sqlite3_close(d) } }
        sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY, nil)
        var stmt: OpaquePointer?
        defer { if let s = stmt { sqlite3_finalize(s) } }
        sqlite3_prepare_v2(db, "SELECT agent_trace_id, agent_tool FROM events", -1, &stmt, nil)
        sqlite3_step(stmt)
        #expect(sqlite3_column_type(stmt, 0) == SQLITE_NULL)
        #expect(sqlite3_column_type(stmt, 1) == SQLITE_NULL)
    }

    @Test("Partial index idx_events_trace excludes NULL rows (audit B1 cascade)")
    func partialIndexCorrect() async throws {
        let path = Self.tempPath()
        defer { try? FileManager.default.removeItem(atPath: path) }
        let store = try EventStore(path: path)

        // Three events: 2 with trace, 1 without.
        for i in 0..<3 {
            var e = Event(
                eventCategory: .process, eventType: .start,
                eventAction: "exec", process: Self.sampleProcess()
            )
            if i < 2 {
                e.enrichments[TraceCorrelator.EnrichmentKey.traceId] = String(repeating: "a", count: 32)
                e.enrichments[TraceCorrelator.EnrichmentKey.agentTool] = "claude_code"
                e.enrichments[TraceCorrelator.EnrichmentKey.confidence] = "traceparent"
            }
            try await store.insert(event: e)
        }

        // Query the partial index directly via the SQL planner.
        var db: OpaquePointer?
        defer { if let d = db { sqlite3_close(d) } }
        sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY, nil)
        var stmt: OpaquePointer?
        defer { if let s = stmt { sqlite3_finalize(s) } }
        sqlite3_prepare_v2(db,
            "SELECT COUNT(*) FROM events WHERE agent_trace_id IS NOT NULL",
            -1, &stmt, nil)
        sqlite3_step(stmt)
        #expect(sqlite3_column_int(stmt, 0) == 2)
    }
}
