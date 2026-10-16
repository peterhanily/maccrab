import Foundation
import Testing
import os
@testable import MacCrabCore
@testable import MacCrabAgentKit

@Suite("Immutable merged-pipeline envelopes preserve value and loss semantics")
struct EventPipelineEnvelopeTests {
    private func event(_ index: Int, lane: EventPipelineLane = .file) -> Event {
        let id = UUID(uuid: (0xA7, 0, 0, 0, 0, 0, 0x40, 0, 0x80, 0, 0, 0,
                            0, 0, UInt8(truncatingIfNeeded: index >> 8), UInt8(truncatingIfNeeded: index)))
        let time = Date(timeIntervalSince1970: 1_700_000_000)
        return Event(
            id: id, timestamp: time, eventCategory: .file,
            eventType: .deletion, eventAction: lane == .file ? "unlink" : "open",
            process: MacCrabCore.ProcessInfo(
                pid: 101, ppid: 100, rpid: 100, name: "inert-envelope",
                executable: "/synthetic/envelope", commandLine: "inert-envelope",
                args: ["inert"], workingDirectory: "/synthetic", userId: 501,
                userName: "synthetic", groupId: 20, startTime: time),
            file: FileInfo(path: "/synthetic/item", name: "item", directory: "/synthetic",
                           action: lane == .file ? .delete : .open),
            enrichments: ["inert": "original"], severity: .low,
            ruleMatches: [.init(ruleId: "inert", ruleName: "Inert", severity: .low,
                                description: "Synthetic value only")])
    }

    @Test("Queue slots are references while Event copies retain COW value isolation")
    func compactSlotAndValueIsolation() async throws {
        #expect(MemoryLayout<EventPipelineEnvelope>.stride == MemoryLayout<UnsafeRawPointer>.stride)
        var original = event(1)
        let expected = original
        let envelope = EventPipelineEnvelope(source: .endpointSecurity, event: original)
        original.enrichments["inert"] = "producer change"
        original.ruleMatches.removeAll()
        original.severity = .critical
        let (stream, continuation) = AsyncStream<EventPipelineEnvelope>.makeStream(
            bufferingPolicy: .bufferingNewest(1))
        defer { continuation.finish() }
        continuation.yield(envelope)
        var iterator = stream.makeAsyncIterator()
        let value = await iterator.next()
        let received = try #require(value)
        var consumer = received.event
        consumer.enrichments["inert"] = "consumer change"
        consumer.ruleMatches.removeAll()
        consumer.severity = .high
        #expect(received.event == expected)
        #expect(envelope.event == expected)
        #expect(received.source == .endpointSecurity)
    }

    @Test("Both lanes preserve distinct FIFO payloads, OLD identity and exact accounting",
          arguments: [EventPipelineLane.priority, .file])
    func fifoAndOldEviction(lane: EventPipelineLane) async throws {
        let (stream, continuation) = AsyncStream<EventPipelineEnvelope>.makeStream(
            bufferingPolicy: .bufferingNewest(3))
        defer { continuation.finish() }
        let telemetry = EventPipelineTelemetry()
        for index in 0..<5 {
            let producer: EventPipelineSource = index < 2 ? .endpointSecurity : .network
            let envelope = EventPipelineEnvelope(source: producer, event: event(index, lane: lane))
            telemetry.recordYield(envelope, lane: lane) {
                let result = continuation.yield(envelope)
                switch result {
                case .enqueued:
                    #expect(index < 3)
                case .dropped(let old):
                    #expect(index >= 3)
                    #expect(old.event == event(index - 3, lane: lane))
                    #expect(old.source == .endpointSecurity)
                case .terminated:
                    Issue.record("unexpected termination")
                @unknown default:
                    Issue.record("unclassified yield")
                }
                return result
            }
        }
        let full = telemetry.snapshot()
        #expect(full.offeredByLane[lane.key] == 5)
        #expect(full.mergedDroppedByLane[lane.key] == 2)
        #expect(full.mergedDroppedBySourceAndLane[EventPipelineSource.endpointSecurity.key]?[lane.key] == 2)
        #expect(full.mergedDroppedBySourceAndLane[EventPipelineSource.network.key]?[lane.key] == 0)
        #expect(full.backlogEstimateByLane[lane.key] == 3)
        #expect(full.detectionInputDroppedTotal == 2)
        // Finishing preserves buffered survivors and makes a faulty missing-item
        // read return nil rather than leaving this fixture suspended indefinitely.
        continuation.finish()
        var iterator = stream.makeAsyncIterator()
        for index in 2..<5 {
            let value = await iterator.next()
            let received = try #require(value)
            #expect(received.event == event(index, lane: lane))
            #expect(received.source == .network)
            telemetry.recordDequeued(lane: lane)
            telemetry.recordCompleted(lane: lane, elapsedNanos: 0)
        }
        let end = await iterator.next()
        #expect(end == nil)
        let drained = telemetry.snapshot()
        #expect(drained.dequeuedByLane[lane.key] == 3)
        #expect(drained.completedByLane[lane.key] == 3)
        #expect(drained.latencySampleCountByLane[lane.key] == 3)
        #expect(drained.backlogEstimateByLane[lane.key] == 0)
        #expect(drained.inFlightByLane[lane.key] == 0)
        #expect(drained.handoffsInFlightByLane[lane.key] == 0)
        #expect(drained.detectionInputDroppedTotal == 2)
    }

    @Test("Dropped and drained payload objects release while the queue stays alive",
          arguments: [EventPipelineLane.priority, .file])
    func releasesPayloadOwnership(lane: EventPipelineLane) async throws {
        let (stream, continuation) = AsyncStream<EventPipelineEnvelope>.makeStream(
            bufferingPolicy: .bufferingNewest(1))
        defer { continuation.finish() }
        let telemetry = EventPipelineTelemetry()
        var offered: EventPipelineEnvelope? = EventPipelineEnvelope(source: .tcc, event: event(1, lane: lane))
        weak var evicted = offered
        telemetry.yield(try #require(offered), to: continuation, lane: lane)
        offered = nil
        #expect(evicted != nil)
        telemetry.yield(EventPipelineEnvelope(source: .network, event: event(2, lane: lane)),
                        to: continuation, lane: lane)
        #expect(evicted == nil)
        evicted = nil // Explicit mutation also supports pre-weak-let Swift versions.
        var iterator = stream.makeAsyncIterator()
        var received = await iterator.next()
        weak var consumed = received
        #expect(consumed != nil)
        #expect(received?.event == event(2, lane: lane))
        received = nil
        #expect(consumed == nil)
        consumed = nil
        withExtendedLifetime((stream, continuation, iterator, telemetry)) {}
    }

    @Test("Finished queues reject new offers without retaining or hiding loss",
          arguments: [EventPipelineLane.priority, .file])
    func finishedOffer(lane: EventPipelineLane) {
        let (stream, continuation) = AsyncStream<EventPipelineEnvelope>.makeStream(
            bufferingPolicy: .bufferingNewest(1))
        continuation.finish()
        let telemetry = EventPipelineTelemetry()
        var offered: EventPipelineEnvelope? = EventPipelineEnvelope(source: .unifiedLog, event: event(9, lane: lane))
        weak var rejected = offered
        if let offered { telemetry.yield(offered, to: continuation, lane: lane) }
        offered = nil
        #expect(rejected == nil)
        rejected = nil
        let snapshot = telemetry.snapshot()
        #expect(snapshot.offeredByLane[lane.key] == 1)
        #expect(snapshot.mergedTerminatedBySourceAndLane[EventPipelineSource.unifiedLog.key]?[lane.key] == 1)
        #expect(snapshot.backlogEstimateByLane[lane.key] == 0)
        #expect(snapshot.detectionInputDroppedTotal == 1)
        withExtendedLifetime((stream, continuation)) {}
    }

    @Test("Cancelled consumers terminate admission and release rejected payloads",
          arguments: [EventPipelineLane.priority, .file])
    func cancellation(lane: EventPipelineLane) async {
        let cancelled = OSAllocatedUnfairLock(initialState: false)
        let (stream, continuation) = AsyncStream<EventPipelineEnvelope>.makeStream(
            bufferingPolicy: .bufferingNewest(1))
        defer { continuation.finish() }
        continuation.onTermination = { termination in
            if case .cancelled = termination { cancelled.withLock { $0 = true } }
        }
        let task = Task {
            withUnsafeCurrentTask { $0?.cancel() }
            var iterator = stream.makeAsyncIterator()
            return await iterator.next() == nil
        }
        let ended = await task.value
        #expect(ended)
        #expect(cancelled.withLock { $0 })
        let telemetry = EventPipelineTelemetry()
        var offered: EventPipelineEnvelope? = EventPipelineEnvelope(source: .tcc, event: event(10, lane: lane))
        weak var rejected = offered
        if let offered { telemetry.yield(offered, to: continuation, lane: lane) }
        offered = nil
        #expect(rejected == nil)
        rejected = nil
        let snapshot = telemetry.snapshot()
        #expect(snapshot.mergedTerminatedByLane[lane.key] == 1)
        #expect(snapshot.backlogEstimateByLane[lane.key] == 0)
        #expect(snapshot.detectionInputDroppedTotal == 1)
        withExtendedLifetime((stream, continuation)) {}
    }
}
