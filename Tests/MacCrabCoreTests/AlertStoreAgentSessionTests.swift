// AlertStoreAgentSessionTests.swift
//
// Wave-3 P2 alert rail: an alert carries the durable agent session id of
// the activity that tripped it (lifted from the triggering event in
// AlertSink). Pins that the column round-trips and that
// alerts(forAgentSession:) isolates + time-orders a session's alerts.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("AlertStore agent-session rail")
struct AlertStoreAgentSessionTests {

    private func tempStore() throws -> (AlertStore, URL) {
        let dir = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("alert-session-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return (try AlertStore(directory: dir.path), dir)
    }

    private func alert(session: String?, at ts: Date) -> Alert {
        Alert(
            timestamp: ts,
            ruleId: "test.rule",
            ruleTitle: "probe",
            severity: .high,
            eventId: UUID().uuidString,
            aiToolSessionId: session
        )
    }

    @Test("ai_tool_session_id round-trips through insert + read")
    func roundTrips() async throws {
        let (store, dir) = try tempStore()
        defer { try? FileManager.default.removeItem(at: dir) }

        let a = alert(session: "sess-xyz", at: Date())
        try await store.insert(alert: a)
        let back = try await store.alert(id: a.id)
        #expect(back?.aiToolSessionId == "sess-xyz")
    }

    @Test("alerts(forAgentSession:) isolates + time-orders, excludes unstamped")
    func sessionQuery() async throws {
        let (store, dir) = try tempStore()
        defer { try? FileManager.default.removeItem(at: dir) }

        let t0 = Date(timeIntervalSince1970: 1_700_000_000)
        try await store.insert(alert: alert(session: "S1", at: t0.addingTimeInterval(2)))
        try await store.insert(alert: alert(session: "S1", at: t0.addingTimeInterval(1)))
        try await store.insert(alert: alert(session: "S2", at: t0.addingTimeInterval(3)))
        try await store.insert(alert: alert(session: nil, at: t0.addingTimeInterval(4)))

        let s1 = try await store.alerts(forAgentSession: "S1")
        #expect(s1.count == 2)
        #expect(s1.first!.timestamp < s1.last!.timestamp)   // ascending

        #expect(try await store.alerts(forAgentSession: "S2").count == 1)
        #expect(try await store.alerts(forAgentSession: "nope").isEmpty)
    }
}
