// EventLoopStageAwaitTests.swift
// v1.22.7 lane-tracegraph — per-stage await accounting for the two detection
// lanes, and the source-level wiring that keeps TraceGraph off the lane
// critical path (the repo has no in-process DaemonState harness, so the
// daemon-side wiring is pinned the same way the existing lane-identity test
// pins the consumer mapping).

import Foundation
import Testing
@testable import MacCrabAgentKit
@testable import MacCrabCore

@Suite("Event-loop stage await accounting")
struct EventLoopStageAwaitTests {

    private static func repositorySource(_ relativePath: String) throws -> String {
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent() // MacCrabCoreTests
            .deletingLastPathComponent() // Tests
            .deletingLastPathComponent() // repository
        return try String(
            contentsOf: root.appendingPathComponent(relativePath),
            encoding: .utf8
        )
    }

    @Test("per-stage awaited nanoseconds accumulate by lane and the remainder is attributed to `other`")
    func stageAwaitsAccumulateByLane() {
        let telemetry = EventPipelineTelemetry()

        var sample = EventPipelineStageAwaits()
        sample.add(.collectorRegistry, nanos: 1_000)
        sample.add(.enrichmentReservation, nanos: 500)
        sample.add(.enricher, nanos: 2_000)
        sample.add(.journalBaseAdmission, nanos: 3_000)
        sample.add(.rules, nanos: 5_000)
        sample.add(.sequences, nanos: 700)
        sample.add(.settlement, nanos: 1_300)
        sample.add(.traceGraphHandoff, nanos: 200)
        #expect(sample.awaitedTotal == 13_700)

        telemetry.recordCompleted(lane: .priority, elapsedNanos: 20_000, stageAwaits: sample)
        telemetry.recordCompleted(lane: .priority, elapsedNanos: 20_000, stageAwaits: sample)
        // A remainder can never go negative: an elapsed time below the awaited
        // sum (clock granularity) attributes zero to `other`.
        telemetry.recordCompleted(lane: .file, elapsedNanos: 10_000, stageAwaits: sample)
        telemetry.recordCompleted(lane: .file, elapsedNanos: 100)

        let snapshot = telemetry.snapshot()
        let priority = snapshot.stageAwaitNanosByLaneAndStage["priority"]
        let file = snapshot.stageAwaitNanosByLaneAndStage["file"]
        #expect(priority?["collector_registry"] == 2_000)
        #expect(priority?["enrichment_reservation"] == 1_000)
        #expect(priority?["enricher"] == 4_000)
        #expect(priority?["journal_base_admission"] == 6_000)
        #expect(priority?["rules"] == 10_000)
        #expect(priority?["sequences"] == 1_400)
        #expect(priority?["settlement"] == 2_600)
        #expect(priority?["tracegraph_handoff"] == 400)
        #expect(priority?["other"] == 12_600)
        #expect(file?["rules"] == 5_000)
        #expect(file?["other"] == 100)

        // The limiting stage is nameable from the heartbeat alone.
        let limiting = priority?
            .filter { $0.key != "other" }
            .max { $0.value < $1.value }?.key
        #expect(limiting == "rules")
        for stage in EventPipelineStage.allCases {
            #expect(priority?[stage.key] != nil, "missing stage \(stage.key)")
            #expect(file?[stage.key] != nil, "missing stage \(stage.key)")
        }
        #expect(snapshot.completedByLane["priority"] == 2)
        #expect(snapshot.completedByLane["file"] == 2)
    }

    @Test("record(_:startedAt:) charges elapsed monotonic time to exactly one stage")
    func recordChargesElapsedTime() {
        var sample = EventPipelineStageAwaits()
        let started = DispatchTime.now().uptimeNanoseconds
        sample.record(.sequences, startedAt: started)
        sample.record(.rules, startedAt: DispatchTime.now().uptimeNanoseconds)
        #expect(sample.nanos(for: .sequences) == sample.awaitedTotal - sample.nanos(for: .rules))
        #expect(sample.nanos(for: .collectorRegistry) == 0)
        #expect(sample.nanos(for: .other) == 0, "other is derived at completion, never recorded")
        sample.add(.enricher, nanos: UInt64.max)
        sample.add(.enricher, nanos: 1)
        #expect(sample.nanos(for: .enricher) == UInt64.max, "saturates instead of wrapping")
    }

    @Test("the lane loop times every listed stage and hands TraceGraph off without awaiting it")
    func laneLoopWiring() throws {
        let eventLoop = try Self.repositorySource("Sources/MacCrabAgentKit/EventLoop.swift")
        for stage in EventPipelineStage.allCases where stage != .other {
            let marker = "stageAwaits.record(.\(stage), startedAt:"
            #expect(eventLoop.components(separatedBy: marker).count - 1 == 1,
                    "stage \(stage) must be timed exactly once in the lane loop")
        }
        #expect(!eventLoop.contains("await bridge.process(enrichedEvent)"),
                "the lane must not await TraceGraph ingestion inline")
        // Inline derived work is charged only when the detection plane was
        // saturated and the work actually ran on the lane.
        #expect(eventLoop.contains("if notarizationAdmission == .ranInlineOnOverload {"))
        // The heartbeat reads the hand-off queue before the rolling writer so
        // `ingest_events_total >= completed - filtered - rejected` holds.
        let timersSource = try Self.repositorySource("Sources/MacCrabAgentKit/DaemonTimers.swift")
        let queueRead = try #require(timersSource.range(of: "let q = bridge.ingestQueueTelemetry()"))
        let writerRead = try #require(timersSource.range(of: "let w = await bridge.writeTelemetry()"))
        #expect(queueRead.lowerBound < writerRead.lowerBound)
        #expect(eventLoop.contains("bridge.offer(enrichedEvent)"))
        #expect(eventLoop.contains("static func serviceTraceGraphIngest(state: DaemonState)"))
        #expect(eventLoop.contains("await bridge.runIngestService"))
        #expect(eventLoop.contains("stageAwaits: stageAwaits"))

        let bootstrap = try Self.repositorySource("Sources/MacCrabAgentKit/DaemonBootstrap.swift")
        #expect(bootstrap.contains("spawnGraphIngestConsumer("))
        #expect(bootstrap.contains("await EventLoop.serviceTraceGraphIngest(state: handles.state)"))
        #expect(bootstrap.contains("bridge.finishIngestQueue()"))

        let lifecycle = try Self.repositorySource("Sources/MacCrabAgentKit/DaemonLifecycle.swift")
        #expect(lifecycle.contains("func spawnGraphIngestConsumer("))
        #expect(lifecycle.contains("graphIngestFinish?()"),
                "shutdown must finish the graph queue only after both lanes have returned")

        let timers = try Self.repositorySource("Sources/MacCrabAgentKit/DaemonTimers.swift")
        #expect(timers.contains("\"stage_await_nanos_by_lane_and_stage\": eventPipeline.stageAwaitNanosByLaneAndStage"))
        for key in [
            "ingest_queue_capacity",
            "ingest_queue_handoffs_total",
            "ingest_queue_skipped_non_graph_total",
            "ingest_queue_offered_total",
            "ingest_queue_dropped_total",
            "ingest_queue_terminated_total",
            "ingest_queue_dequeued_total",
            "ingest_queue_completed_total",
            "ingest_queue_backlog",
            "ingest_queue_in_flight",
            "ingest_latched_shed_total",
            "ingest_admission_latched",
            "ingest_admission_probes_total",
            "ingest_admission_latch_arms_total",
            "ingest_latched_passthrough_total",
            "ingest_queue_filtered_total",
            "ingest_queue_rejected_total",
            "ingest_queue_loss_total",
            "ingest_queue_loss_recent",
            "ingest_queue_loss_last_at_unix",
            "anchor_shed_total",
            "anchor_shed_dedup_suppressed_total",
        ] {
            #expect(timers.contains("d[\"\(key)\"]"), "missing TraceGraph heartbeat field: \(key)")
        }
    }
}
