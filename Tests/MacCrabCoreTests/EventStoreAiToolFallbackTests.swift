// EventStoreAiToolFallbackTests.swift
// v1.12.6 RC2 Wave 9C regression pin — EventStore.insert must populate
// the `ai_tool` column from EITHER canonical enrichment key.
//
// Bug history:
//   - Wave 2A added the `ai_tool` indexed column and bound it via
//     `enrichments[TraceCorrelator.EnrichmentKey.agentTool]`
//     (the `agent_tool` string).
//   - The production writer is AIProcessTracker in EventLoop.swift, which
//     writes the key `"ai_tool"` (not `"agent_tool"`). TraceCorrelator
//     ALSO writes `"agent_tool"` via its own flatten path, but only on
//     TRACEPARENT/lineage correlation hits — a small minority of events.
//   - Field-confirmed on live events.db: every AI-attributed event had
//     `enrichments.ai_tool = "claude_code"` (etc.) in raw_json and zero
//     rows had the indexed `ai_tool` column populated. Rules predicating
//     on the column never matched, even though the data was present in
//     raw_json.
//
// RC2 fix: read both keys with `ai_tool` preferred. These tests pin that
// fallback and ensure both writer paths populate the column.

import Testing
import Foundation
import SQLite3
@testable import MacCrabCore

@Suite("EventStore: ai_tool column reads both canonical keys (v1.12.6 RC2 Wave 9C)")
struct EventStoreAiToolFallbackTests {

    // MARK: - Helpers (mirror EventStoreSchemaV6Tests)

    private static func tempPath() -> String {
        FileManager.default.temporaryDirectory
            .appendingPathComponent("ai-tool-fallback-\(UUID().uuidString).db").path
    }

    private static func makeProcess() -> MacCrabCore.ProcessInfo {
        MacCrabCore.ProcessInfo(
            pid: 4242,
            ppid: 100,
            rpid: 4242,
            name: "node",
            executable: "/usr/local/bin/node",
            commandLine: "node script.js",
            args: ["node", "script.js"],
            workingDirectory: "/Users/alice/project",
            userId: 501,
            userName: "alice",
            groupId: 20,
            startTime: Date(),
            codeSignature: nil,
            ancestors: [
                ProcessAncestor(pid: 100, executable: "/Applications/Claude.app/Contents/MacOS/Claude", name: "Claude"),
            ],
            architecture: "arm64",
            isPlatformBinary: false,
            hashes: nil,
            session: nil
        )
    }

    private static func makeEvent(enrichments: [String: String] = [:]) -> Event {
        Event(
            eventCategory: .process,
            eventType: .start,
            eventAction: "exec",
            process: makeProcess(),
            enrichments: enrichments
        )
    }

    /// Read back the `ai_tool` column for a single inserted row.
    /// Returns nil for SQLITE_NULL, the text otherwise.
    private static func readAiTool(at path: String) -> String? {
        var db: OpaquePointer?
        defer { if let d = db { sqlite3_close(d) } }
        sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY, nil)
        guard let db else { return nil }

        var stmt: OpaquePointer?
        defer { sqlite3_finalize(stmt) }
        guard sqlite3_prepare_v2(db, "SELECT ai_tool FROM events", -1, &stmt, nil) == SQLITE_OK,
              sqlite3_step(stmt) == SQLITE_ROW else {
            return nil
        }
        if sqlite3_column_type(stmt, 0) == SQLITE_NULL { return nil }
        return String(cString: sqlite3_column_text(stmt, 0))
    }

    // MARK: - Tests

    @Test("ai_tool column populates from enrichments['ai_tool'] (production key)")
    func populatesFromAiToolKey() async throws {
        let path = Self.tempPath()
        defer { try? FileManager.default.removeItem(atPath: path) }
        let store = try EventStore(path: path)

        // The AIProcessTracker writer path — EventLoop.swift:89,97.
        let event = Self.makeEvent(enrichments: ["ai_tool": "claude_code"])
        try await store.insert(event: event)

        #expect(Self.readAiTool(at: path) == "claude_code")
    }

    @Test("ai_tool column falls back to enrichments['agent_tool'] (legacy TraceCorrelator key)")
    func fallsBackToAgentToolKey() async throws {
        let path = Self.tempPath()
        defer { try? FileManager.default.removeItem(atPath: path) }
        let store = try EventStore(path: path)

        // The TraceCorrelator.flatten() writer path — produced via
        // EnrichmentKey.agentTool = "agent_tool".
        let event = Self.makeEvent(
            enrichments: [TraceCorrelator.EnrichmentKey.agentTool: "cursor"]
        )
        try await store.insert(event: event)

        #expect(Self.readAiTool(at: path) == "cursor")
    }

    @Test("ai_tool column prefers 'ai_tool' over 'agent_tool' when both keys are present")
    func prefersAiToolWhenBothPresent() async throws {
        let path = Self.tempPath()
        defer { try? FileManager.default.removeItem(atPath: path) }
        let store = try EventStore(path: path)

        // Both writers fired on the same event (e.g. a child of an AI
        // tool that also matched a TRACEPARENT correlation). The
        // production "ai_tool" key wins so the column reflects the
        // most-canonical (AIProcessTracker-attributed) value.
        let event = Self.makeEvent(enrichments: [
            "ai_tool": "claude_code",
            TraceCorrelator.EnrichmentKey.agentTool: "cursor",
        ])
        try await store.insert(event: event)

        #expect(Self.readAiTool(at: path) == "claude_code")
    }

    @Test("ai_tool column is NULL when neither key is set")
    func nullWhenNeitherKeySet() async throws {
        let path = Self.tempPath()
        defer { try? FileManager.default.removeItem(atPath: path) }
        let store = try EventStore(path: path)

        let event = Self.makeEvent(enrichments: ["mcp_server_name": "github"])
        try await store.insert(event: event)

        #expect(Self.readAiTool(at: path) == nil)
    }
}
