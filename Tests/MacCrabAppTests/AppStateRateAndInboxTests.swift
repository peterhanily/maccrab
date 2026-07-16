// AppStateRateAndInboxTests.swift
// MacCrabAppTests
//
// Deep-audit reconciliation (2026-07-16):
//  - eventsPerSecond finding (2814): the first poll had no baseline
//    (previousEventCount started at 0), so the first delta was the ENTIRE
//    event backlog → a spurious events/sec spike. `eventsPerSecondFrom`
//    returns nil until primed so the caller skips that first publish.
//  - Retention "Clear Now" finding (2568): the dashboard opens alerts.db
//    read-only, so a direct prune always failed. The app now drops a
//    `prune-alerts-*.json` inbox request for the root daemon to apply.
//  - Agent-traces toggle finding (1695): `pkill -HUP com.maccrab.agent` is
//    EPERM cross-uid, so the toggle was a no-op on release. The app now
//    drops an `apply-agent-traces-*.json` inbox request instead.

import Testing
import Foundation
@testable import MacCrabApp

@Suite("AppState — events/sec baseline + inbox request writers")
struct AppStateRateAndInboxTests {

    // MARK: - eventsPerSecondFrom (finding 2814)

    @Test("first sample (nil baseline) returns nil — no spurious first-poll spike")
    func firstSampleSkips() {
        // 40k events already in the DB must NOT publish as 40k/s on poll #1.
        #expect(AppState.eventsPerSecondFrom(previousCount: nil, currentCount: 40_000, elapsedSeconds: 5) == nil)
    }

    @Test("steady state with no new events reports 0")
    func steadyStateZero() {
        #expect(AppState.eventsPerSecondFrom(previousCount: 100, currentCount: 100, elapsedSeconds: 5) == 0)
    }

    @Test("a real delta divides by elapsed seconds")
    func realRate() {
        #expect(AppState.eventsPerSecondFrom(previousCount: 100, currentCount: 160, elapsedSeconds: 5) == 12)
    }

    @Test("a tiny positive delta floors at 1 (never rounds a real change to 0)")
    func tinyDeltaFloorsAtOne() {
        #expect(AppState.eventsPerSecondFrom(previousCount: 100, currentCount: 101, elapsedSeconds: 10) == 1)
    }

    @Test("a count that went backwards (e.g. a prune) reports 0, not a negative")
    func negativeDeltaClampsToZero() {
        #expect(AppState.eventsPerSecondFrom(previousCount: 200, currentCount: 100, elapsedSeconds: 5) == 0)
    }

    @Test("elapsed is floored at 1 second (no divide-by-zero on a fast poll)")
    func elapsedFloor() {
        #expect(AppState.eventsPerSecondFrom(previousCount: 0, currentCount: 30, elapsedSeconds: 0) == 30)
    }

    // MARK: - writePruneAlertsRequest (finding 2568)

    @Test("writes a prune-alerts-*.json the daemon poller will match, carrying olderThanDays")
    func writesPruneRequest() throws {
        let tmp = NSTemporaryDirectory() + "maccrab-prune-test-" + UUID().uuidString
        let inbox = tmp + "/inbox"
        defer { try? FileManager.default.removeItem(atPath: tmp) }

        #expect(AppState.writePruneAlertsRequest(inboxDir: inbox, olderThanDays: 30))

        let files = (try? FileManager.default.contentsOfDirectory(atPath: inbox)) ?? []
        // Daemon partition contract: hasPrefix("prune-alerts-") && hasSuffix(".json")
        let matched = files.filter { $0.hasPrefix("prune-alerts-") && $0.hasSuffix(".json") }
        #expect(matched.count == 1)

        let data = try Data(contentsOf: URL(fileURLWithPath: inbox + "/" + matched[0]))
        let obj = try JSONSerialization.jsonObject(with: data) as? [String: Any]
        #expect(obj?["olderThanDays"] as? Int == 30)
        #expect(obj?["requester"] as? String == "MacCrabApp")
    }

    @Test("prune writer reports false on an unwritable path (honest failure)")
    func pruneHonestFailure() {
        let tmpFile = NSTemporaryDirectory() + "maccrab-prune-notdir-" + UUID().uuidString
        FileManager.default.createFile(atPath: tmpFile, contents: Data("x".utf8))
        defer { try? FileManager.default.removeItem(atPath: tmpFile) }
        #expect(!AppState.writePruneAlertsRequest(inboxDir: tmpFile + "/inbox", olderThanDays: 7))
    }

    // MARK: - writeAgentTracesRequest (finding 1695)

    @Test("writes an apply-agent-traces-*.json carrying receiverEnabled + port")
    func writesAgentTracesRequest() throws {
        let tmp = NSTemporaryDirectory() + "maccrab-agenttraces-test-" + UUID().uuidString
        let inbox = tmp + "/inbox"
        defer { try? FileManager.default.removeItem(atPath: tmp) }

        #expect(AppState.writeAgentTracesRequest(inboxDir: inbox, receiverEnabled: true, port: 4318))

        let files = (try? FileManager.default.contentsOfDirectory(atPath: inbox)) ?? []
        let matched = files.filter { $0.hasPrefix("apply-agent-traces-") && $0.hasSuffix(".json") }
        #expect(matched.count == 1)

        let data = try Data(contentsOf: URL(fileURLWithPath: inbox + "/" + matched[0]))
        let obj = try JSONSerialization.jsonObject(with: data) as? [String: Any]
        #expect(obj?["receiverEnabled"] as? Bool == true)
        #expect(obj?["port"] as? Int == 4318)
    }

    @Test("agent-traces writer reports false on an unwritable path (honest failure)")
    func agentTracesHonestFailure() {
        let tmpFile = NSTemporaryDirectory() + "maccrab-agenttraces-notdir-" + UUID().uuidString
        FileManager.default.createFile(atPath: tmpFile, contents: Data("x".utf8))
        defer { try? FileManager.default.removeItem(atPath: tmpFile) }
        #expect(!AppState.writeAgentTracesRequest(inboxDir: tmpFile + "/inbox", receiverEnabled: false, port: 4318))
    }
}
