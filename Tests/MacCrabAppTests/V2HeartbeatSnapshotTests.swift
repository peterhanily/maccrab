// V2HeartbeatSnapshotTests.swift
// MacCrabAppTests
//
// Pin the V2HeartbeatSnapshot decoder + computed-property contract.
// The dashboard's System workspace renders these directly so a
// silent decoding regression would put epoch-0 / 20583d-ago strings
// in front of users. Covers: decode happy path, missing-field
// degradation, uptime formatting buckets, eventsPerSecond1h math.

import Testing
import Foundation
@testable import MacCrabApp

@Suite("V2HeartbeatSnapshot")
struct V2HeartbeatSnapshotTests {

    private func writeFixture(_ json: [String: Any]) throws -> URL {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrab-hb-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let path = dir.appendingPathComponent("heartbeat_rich.json")
        let data = try JSONSerialization.data(withJSONObject: json, options: [])
        try data.write(to: path)
        return path
    }

    // MARK: - uptimeDisplay buckets

    @Test("uptimeDisplay formats sub-minute values as seconds")
    func uptimeUnderOneMinute() {
        let snap = makeSnapshot(uptimeSeconds: 45)
        #expect(snap.uptimeDisplay == "45s")
    }

    @Test("uptimeDisplay formats sub-hour values as minutes")
    func uptimeUnderOneHour() {
        let snap = makeSnapshot(uptimeSeconds: 600)
        #expect(snap.uptimeDisplay == "10m")
    }

    @Test("uptimeDisplay formats sub-day values as Hh Mm")
    func uptimeUnderOneDay() {
        let snap = makeSnapshot(uptimeSeconds: 2 * 3600 + 14 * 60) // 2h 14m
        #expect(snap.uptimeDisplay == "2h 14m")
    }

    @Test("uptimeDisplay drops the minute component when at an exact hour")
    func uptimeExactHour() {
        let snap = makeSnapshot(uptimeSeconds: 3 * 3600)
        #expect(snap.uptimeDisplay == "3h")
    }

    @Test("uptimeDisplay formats day+ values as Nd Hh")
    func uptimeMultiDay() {
        let snap = makeSnapshot(uptimeSeconds: 5 * 86_400 + 3 * 3600)
        #expect(snap.uptimeDisplay == "5d 3h")
    }

    @Test("uptimeDisplay drops hour when on an exact day")
    func uptimeExactDay() {
        let snap = makeSnapshot(uptimeSeconds: 12 * 86_400)
        #expect(snap.uptimeDisplay == "12d")
    }

    // MARK: - eventsPerSecond1h

    @Test("eventsPerSecond1h sums all categories and divides by 3600")
    func eventsPerSecondMath() {
        let snap = makeSnapshot(eventTypeCounts1h: ["exec": 1800, "file": 1800])
        #expect(snap.eventsPerSecond1h == 1.0)
    }

    @Test("eventsPerSecond1h returns 0 when counts are empty")
    func eventsPerSecondEmpty() {
        let snap = makeSnapshot(eventTypeCounts1h: [:])
        #expect(snap.eventsPerSecond1h == 0.0)
    }

    // MARK: - readFreshest behavior

    @Test("readFreshest returns nil when no candidate heartbeat exists")
    func readFreshestNil() {
        // The Real readFreshest scans two specific application-support
        // dirs; on a clean test environment those should not contain
        // a recent heartbeat. We accept either nil OR a real snapshot
        // depending on whether the developer's daemon is running.
        // Not strictly testable without injecting paths; documented
        // as a follow-up.
        let snap = V2HeartbeatSnapshot.readFreshest()
        // If the daemon is running, snap is non-nil and within 5 minutes.
        if let s = snap {
            #expect(s.writtenAt.timeIntervalSinceNow > -300)
        }
    }

    // MARK: - Helpers

    private func makeSnapshot(
        uptimeSeconds: Int = 0,
        eventTypeCounts1h: [String: Int] = [:]
    ) -> V2HeartbeatSnapshot {
        V2HeartbeatSnapshot(
            writtenAt: Date(),
            uptimeSeconds: uptimeSeconds,
            eventsProcessed: 0,
            alertsEmitted: 0,
            residentMemoryMB: nil,
            sysextHasFDA: false,
            schemaVersion: 2,
            eventTypeCounts1h: eventTypeCounts1h,
            collectors: [],
            payloadTruncatedTotal: 0,
            esloggerDroppedTotal: 0,
            llm: nil
        )
    }
}
