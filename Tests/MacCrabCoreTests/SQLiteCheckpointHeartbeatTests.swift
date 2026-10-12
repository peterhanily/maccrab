import Foundation
import Testing
@testable import MacCrabCore
@testable import MacCrabAgentKit

@Suite("SQLite checkpoint fixed heartbeat projection")
struct SQLiteCheckpointHeartbeatTests {
    @Test("Projection preserves unavailable and exact counters without schema or path labels")
    func fixedProjectionIsReadOnlyAndPrivate() throws {
        let missing = SQLiteCheckpointHeartbeat.fields(
            event: nil, alert: nil, tracegraph: nil, graphExplicit: nil)
        #expect(Set(missing.keys) == Set(["event", "alert", "tracegraph"]))
        for key in ["event", "alert", "tracegraph"] {
            let family = try #require(missing[key] as? [String: Any])
            let controlled = try #require(family["controlled"] as? [String: Any])
            #expect(controlled.count == 1 && controlled["available"] as? Bool == false)
        }
        let absentGraph = try #require(missing["tracegraph"] as? [String: Any])
        let absentExplicit = try #require(absentGraph["explicit"] as? [String: Any])
        #expect(absentExplicit.count == 1 && absentExplicit["available"] as? Bool == false)

        let controlled = SQLiteControlledCheckpointSnapshot(
            thresholdPages: 4_000, attemptCount: 9, backoffSkipCount: 7,
            completedCount: 3, admissionDeferralCount: 2,
            pinnedReaderDeferralCount: 3, sqliteFailureCount: 1,
            lastDisposition: .deferredPinnedReader,
            lastSchema: "private-schema-sentinel", lastWalPages: 42,
            lastCheckpointedPages: 40, retryBackoffRemainingCommits: 8,
            active: true)
        let mode: [String: Any] = [
            "requestsTotal": 7, "attemptsTotal": 3, "completedTotal": 1,
            "pinnedDeferralsTotal": 1, "failuresTotal": 1,
            "admissionDeferralsTotal": 2, "unavailableTotal": 2,
            "requestNanosecondsTotal": 100, "requestMaxNanoseconds": 40,
            "sqliteNanosecondsTotal": 50, "sqliteMaxNanoseconds": 20,
            "lastLogFrames": NSNull(), "lastCheckpointedFrames": NSNull(),
        ]
        let explicit = try JSONDecoder().decode(
            CausalGraphCheckpointTelemetry.self,
            from: JSONSerialization.data(withJSONObject: [
                "passive": mode, "restart": mode, "truncate": mode]))
        let fields = SQLiteCheckpointHeartbeat.fields(
            event: controlled, alert: nil, tracegraph: controlled,
            graphExplicit: explicit)
        let event = try #require(fields["event"] as? [String: Any])
        let eventCounters = try #require(event["controlled"] as? [String: Any])
        #expect(eventCounters["available"] as? Bool == true)
        #expect(eventCounters["attempts_total"] as? UInt64 == 9)
        #expect(eventCounters["completed_total"] as? UInt64 == 3)
        #expect(eventCounters["last_disposition"] as? String == "deferredPinnedReader")
        #expect(eventCounters["last_wal_pages"] as? Int32 == 42)
        #expect(eventCounters["active"] as? Bool == true)
        #expect(eventCounters["lastSchema"] == nil && eventCounters["last_schema"] == nil)
        let graph = try #require(fields["tracegraph"] as? [String: Any])
        let explicitFields = try #require(graph["explicit"] as? [String: Any])
        #expect(Set(explicitFields.keys) == Set(["available", "passive", "restart", "truncate"]))
        for key in ["passive", "restart", "truncate"] {
            let counters = try #require(explicitFields[key] as? [String: Any])
            #expect(counters.count == 13)
            #expect(counters["requests_total"] as? UInt64 == 7)
            #expect(counters["attempts_total"] as? UInt64 == 3)
            #expect(counters["request_nanoseconds_total"] as? UInt64 == 100)
            #expect(counters["sqlite_nanoseconds_total"] as? UInt64 == 50)
            #expect(counters["last_log_frames"] is NSNull)
            #expect(counters["last_checkpointed_frames"] is NSNull)
        }
        #expect(JSONSerialization.isValidJSONObject(fields))
        let serialized = try JSONSerialization.data(withJSONObject: fields)
        #expect(!String(decoding: serialized, as: UTF8.self).contains("private-schema-sentinel"))
    }
}
