import Foundation
import Testing
@testable import MacCrabAgentKit

@Suite("Coherent heartbeat clock samples")
struct HeartbeatClockTests {
    private let identity = DaemonProcessIdentity(
        pid: 42, startedAtUnix: 1_000, version: "fixture", build: "fixture",
        startedAtUptime: 100
    )

    @Test("snapshot assembly delay is separate from the paired publication clocks")
    func delayedCollectionDoesNotSkewUptimeInterval() {
        let firstStart = identity.heartbeatClockSample(wallTime: { 1_010 }, monotonicTime: { 110 })
        let first = identity.heartbeatClockSample(wallTime: { 1_014 }, monotonicTime: { 114 })
        let nextStart = identity.heartbeatClockSample(wallTime: { 1_040 }, monotonicTime: { 140 })
        let next = identity.heartbeatClockSample(wallTime: { 1_040.5 }, monotonicTime: { 140.5 })
        #expect(first.elapsed(since: firstStart) == 4)
        #expect(next.elapsed(since: nextStart) == 0.5)
        #expect(next.writtenAtUnix - first.writtenAtUnix == next.engineUptimeSeconds - first.engineUptimeSeconds)
        #expect(first.engineUptimeSeconds == 14)
        #expect(first.writtenAtUnix == 1_014)
    }

    @Test("wall-clock correction does not alter monotonic engine uptime or duration")
    func wallClockChangeRemainsObservable() {
        let before = identity.heartbeatClockSample(wallTime: { 1_010 }, monotonicTime: { 110 })
        let after = identity.heartbeatClockSample(wallTime: { 900 }, monotonicTime: { 140 })
        #expect(after.engineUptimeSeconds - before.engineUptimeSeconds == 30)
        #expect(after.elapsed(since: before) == 30)
        #expect(after.writtenAtUnix - before.writtenAtUnix == -110)
    }

    @Test("each clock is sampled once and the result does not resample on access")
    func immutablePairedRead() {
        var wallReads = 0
        var monotonicReads = 0
        let sample = identity.heartbeatClockSample(
            wallTime: { wallReads += 1; return 1_020 },
            monotonicTime: { monotonicReads += 1; return 120 }
        )
        for _ in 0..<10 {
            #expect(sample.writtenAtUnix == 1_020)
            #expect(sample.engineUptimeSeconds == 20)
        }
        #expect(wallReads == 1)
        #expect(monotonicReads == 1)
    }

    @Test("slow collection cannot refresh old health data for existing readers")
    func completedFieldsPreserveCollectionAge() {
        let start = identity.heartbeatClockSample(wallTime: { 1_010 }, monotonicTime: { 110 })
        let end = identity.heartbeatClockSample(wallTime: { 1_080 }, monotonicTime: { 180 })
        let fields = end.completedCollectionFields(since: start)
        #expect(fields["written_at_unix"] == 1_010)
        #expect(fields["engine_uptime_seconds"] == 10)
        #expect(fields["heartbeat_collection_started_at_unix"] == 1_010)
        #expect(fields["heartbeat_published_at_unix"] == 1_080)
        #expect(fields["heartbeat_collection_duration_seconds"] == 70)
        #expect(1_080 - (fields["written_at_unix"] ?? 1_080) > 60)
    }
}
