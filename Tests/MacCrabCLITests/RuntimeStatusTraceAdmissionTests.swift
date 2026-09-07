import Foundation
import Testing
@testable import MacCrabCore
@testable import maccrab_mcp

@Suite("Shared status Agent Trace admission and provenance")
struct RuntimeStatusTraceAdmissionTests {
    private func directory() throws -> URL {
        let path = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrab-trace-status-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: path, withIntermediateDirectories: true)
        return path
    }

    private func writeHeartbeat(directory: URL, writtenAt: Date, blocked: Bool) throws {
        let heartbeat: [String: Any] = [
            "schema_version": 5,
            "engine_pid": 42,
            "engine_started_at_unix": writtenAt.timeIntervalSince1970 - 10,
            "engine_version": "1.22.0",
            "engine_build": "fixture",
            "written_at_unix": writtenAt.timeIntervalSince1970,
            "traces_storage_admission": [
                "enabled": blocked,
                "blocked": blocked,
                "store_available": true,
                "startup_blocked": false,
                "reason": blocked ? "footprint_limit" : "receiver_disabled",
                "shed_mutations_total": 7,
            ],
        ]
        let data = try JSONSerialization.data(withJSONObject: heartbeat)
        try data.write(to: directory.appendingPathComponent("heartbeat.json"))
        try data.write(to: directory.appendingPathComponent("heartbeat_rich.json"))
    }

    private func statusPayload(directory: URL, now: Date) async throws -> [String: Any] {
        let response = try #require(
            await mcpRuntimeStatus(directory: directory.path, now: now) as? [String: Any]
        )
        #expect(response["isError"] as? Bool != true)
        let content = try #require(response["content"] as? [[String: Any]])
        let text = try #require(content.first?["text"] as? String)
        return try #require(JSONSerialization.jsonObject(with: Data(text.utf8)) as? [String: Any])
    }

    @Test("Current status preserves disabled and blocked admission independently of trust", arguments: [false, true])
    func currentAdmission(blocked: Bool) async throws {
        let path = try directory()
        defer { try? FileManager.default.removeItem(at: path) }
        let writtenAt = Date(timeIntervalSince1970: 1_700_000_000)
        try writeHeartbeat(directory: path, writtenAt: writtenAt, blocked: blocked)
        let now = writtenAt.addingTimeInterval(1)
        let document = try await RuntimeStatusDocument.read(directory: path.path, now: now)
        #expect(document.agentTraceTrust == .unauthenticatedSelfReported)
        let shared = try #require(document.currentHealth?.traceStoreStorageAdmission)
        #expect(shared.blocked == blocked)
        #expect(shared.enabled == blocked)
        #expect(shared.shedMutationsTotal == 7)

        let payload = try await statusPayload(directory: path, now: now)
        #expect(payload["agent_trace_trust"] as? String == "unauthenticated_self_reported")
        let health = try #require(payload["current_health"] as? [String: Any])
        let admission = try #require(health["traces_storage_admission"] as? [String: Any])
        #expect(admission["blocked"] as? Bool == blocked)
        #expect(admission["enabled"] as? Bool == blocked)
        #expect(admission["reason"] as? String == (blocked ? "footprint_limit" : "receiver_disabled"))
        #expect(admission["shed_mutations_total"] as? Int == 7)
    }

    @Test("Absent and stale health retain the provenance label without inventing admission")
    func unavailableAdmission() async throws {
        let path = try directory()
        defer { try? FileManager.default.removeItem(at: path) }
        let writtenAt = Date(timeIntervalSince1970: 1_700_000_000)
        let absent = try await statusPayload(directory: path, now: writtenAt)
        #expect(absent["liveness"] as? String == "unavailable")
        #expect(absent["current_health"] == nil)
        #expect(absent["agent_trace_trust"] as? String == "unauthenticated_self_reported")

        try writeHeartbeat(directory: path, writtenAt: writtenAt, blocked: true)
        let stale = try await statusPayload(directory: path, now: writtenAt.addingTimeInterval(121))
        #expect(stale["liveness"] as? String == "stale_or_unknown")
        #expect(stale["current_health"] == nil)
        #expect(stale["agent_trace_trust"] as? String == "unauthenticated_self_reported")
    }
}
