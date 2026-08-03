import Foundation
import Testing
@testable import MacCrabAgentKit
@testable import MacCrabCore

@Suite("Event-pipeline causality telemetry")
struct EventPipelineTelemetryTests {
    @Test("source, lane, backlog, in-flight, and latency accounting stay distinct")
    func snapshotSeparatesEveryCausalityStage() {
        let telemetry = EventPipelineTelemetry()

        for _ in 0..<100 {
            telemetry.recordOffered(source: .unifiedLog, lane: .priority)
        }
        for _ in 0..<25 {
            telemetry.recordOffered(source: .endpointSecurity, lane: .file)
        }
        for _ in 0..<4 {
            telemetry.recordDropped(source: .unifiedLog, lane: .priority)
        }
        for _ in 0..<2 {
            telemetry.recordDropped(source: .endpointSecurity, lane: .file)
        }

        for _ in 0..<90 { telemetry.recordDequeued(lane: .priority) }
        for _ in 0..<20 { telemetry.recordDequeued(lane: .file) }
        for _ in 0..<89 {
            telemetry.recordCompleted(lane: .priority, elapsedNanos: 800_000)
        }
        telemetry.recordCompleted(lane: .priority, elapsedNanos: 9_000_000)
        for _ in 0..<19 {
            telemetry.recordCompleted(lane: .file, elapsedNanos: 3_000_000)
        }

        let snapshot = telemetry.snapshot()

        #expect(snapshot.offeredBySource["UnifiedLogCollector"] == 100)
        #expect(snapshot.offeredBySource["ESCollector"] == 25)
        #expect(snapshot.offeredBySourceAndLane["UnifiedLogCollector"]?["priority"] == 100)
        #expect(snapshot.offeredBySourceAndLane["UnifiedLogCollector"]?["file"] == 0)
        #expect(snapshot.offeredBySourceAndLane["ESCollector"]?["file"] == 25)
        #expect(snapshot.droppedBySourceAndLane["UnifiedLogCollector"]?["priority"] == 4)
        #expect(snapshot.droppedBySourceAndLane["ESCollector"]?["file"] == 2)
        #expect(snapshot.offeredByLane["priority"] == 100)
        #expect(snapshot.offeredByLane["file"] == 25)
        #expect(snapshot.dequeuedByLane["priority"] == 90)
        #expect(snapshot.completedByLane["file"] == 19)
        #expect(snapshot.backlogEstimateByLane["priority"] == 6)
        #expect(snapshot.backlogEstimateByLane["file"] == 3)
        #expect(snapshot.inFlightByLane["priority"] == 0)
        #expect(snapshot.inFlightByLane["file"] == 1)
        #expect(snapshot.processingP99MicrosByLane["priority"] == 16_000)
        #expect(snapshot.processingP99MicrosByLane["file"] == 4_000)
        #expect(snapshot.latencySampleCountByLane == snapshot.completedByLane)
    }

    @Test("rule boundary is event-cardinality and cross-tabbed by lane/category")
    func ruleEvaluationBoundaryAccounting() {
        let telemetry = EventPipelineTelemetry()

        telemetry.recordRuleEvaluationReached(lane: .priority, category: .process)
        telemetry.recordRuleEvaluationCompleted(lane: .priority, category: .process)
        telemetry.recordRuleEvaluationReached(lane: .priority, category: .file)
        telemetry.recordRuleEvaluationReached(lane: .file, category: .file)
        telemetry.recordRuleEvaluationCompleted(lane: .file, category: .file)

        let snapshot = telemetry.snapshot()
        #expect(snapshot.ruleEvaluationReachedByLaneAndCategory["priority"]?["process"] == 1)
        #expect(snapshot.ruleEvaluationCompletedByLaneAndCategory["priority"]?["process"] == 1)
        #expect(snapshot.ruleEvaluationReachedByLaneAndCategory["priority"]?["file"] == 1)
        #expect(snapshot.ruleEvaluationCompletedByLaneAndCategory["priority"]?["file"] == 0)
        #expect(snapshot.ruleEvaluationReachedByLaneAndCategory["file"]?["file"] == 1)
        #expect(snapshot.ruleEvaluationCompletedByLaneAndCategory["file"]?["file"] == 1)
        #expect(snapshot.ruleEvaluationReachedByLaneAndCategory["file"]?["network"] == 0,
                "all fixed categories must be emitted even before first use")
    }

    @Test("defensive snapshot arithmetic never underflows or wraps")
    func snapshotSubtractionSaturatesAtZero() {
        let telemetry = EventPipelineTelemetry()
        telemetry.recordOffered(source: .endpointSecurity, lane: .priority)
        telemetry.recordDequeued(lane: .priority)
        telemetry.recordCompleted(lane: .priority, elapsedNanos: 100)

        // dropped + dequeued overflows UInt64 unless the intermediate sum is
        // saturating. A wrapped intermediate would report a positive backlog.
        let upstream = EventCollectorBufferSnapshot(
            offeredByLane: ["priority": UInt64.max, "file": UInt64.max],
            droppedByLane: ["priority": UInt64.max, "file": UInt64.max],
            terminatedByLane: ["priority": UInt64.max, "file": UInt64.max],
            capacity: 2
        )
        let snapshot = telemetry.snapshot(upstreamBuffers: [.endpointSecurity: upstream])
        #expect(snapshot.backlogEstimateByLane["priority"] == 0)
        #expect(snapshot.backlogEstimateByLane["file"] == 0)
        #expect(snapshot.inFlightByLane["priority"] == 0)
        #expect(snapshot.latencySampleCountByLane == snapshot.completedByLane)
        #expect(snapshot.detectionInputDroppedTotal == UInt64.max)
    }

    @Test("collector overflow attributes the OLD event's final lane")
    func collectorOverflowUsesEvictedOldEvent() {
        var continuation: AsyncStream<Event>.Continuation!
        let stream = AsyncStream<Event>(bufferingPolicy: .bufferingNewest(2)) {
            continuation = $0
        }
        let telemetry = EventCollectorBufferTelemetry(capacity: 2)
        let oldFile = makeEvent(category: .file, action: "write", pid: 1)
        let priorityOpen = makeEvent(category: .file, action: "open", pid: 2)
        let newFile = makeEvent(category: .file, action: "rename", pid: 3)

        for event in [oldFile, priorityOpen, newFile] {
            let result = continuation.yield(event)
            telemetry.recordYield(offered: event, result: result)
        }
        let snapshot = telemetry.snapshot()

        #expect(snapshot.offeredByLane == ["priority": 1, "file": 2])
        #expect(snapshot.droppedByLane == ["priority": 0, "file": 1])
        #expect(snapshot.terminatedTotal == 0)
        #expect(snapshot.capacity == 2)
        _ = stream
    }

    @Test("mixed-source downstream overflow attributes the evicted envelope")
    func downstreamOverflowUsesEvictedSource() {
        var continuation: AsyncStream<EventPipelineEnvelope>.Continuation!
        let stream = AsyncStream<EventPipelineEnvelope>(
            bufferingPolicy: .bufferingNewest(2)
        ) { continuation = $0 }
        let telemetry = EventPipelineTelemetry()
        let event = makeEvent(category: .process, action: "exec", pid: 10)

        telemetry.yield(
            EventPipelineEnvelope(source: .endpointSecurity, event: event),
            to: continuation,
            lane: .priority
        )
        telemetry.yield(
            EventPipelineEnvelope(source: .unifiedLog, event: event),
            to: continuation,
            lane: .priority
        )
        telemetry.yield(
            EventPipelineEnvelope(source: .tcc, event: event),
            to: continuation,
            lane: .priority
        )

        let snapshot = telemetry.snapshot()
        #expect(snapshot.offeredBySource["TCCMonitor"] == 1)
        #expect(snapshot.mergedDroppedBySourceAndLane["ESCollector"]?["priority"] == 1)
        #expect(snapshot.mergedDroppedBySourceAndLane["TCCMonitor"]?["priority"] == 0)
        #expect(snapshot.backlogEstimateByLane["priority"] == 2)
        #expect(snapshot.detectionInputDroppedTotal == 1)
        _ = stream
    }

    @Test("yield after termination is observable and never creates backlog")
    func terminatedYieldIsRejectedInput() {
        var continuation: AsyncStream<EventPipelineEnvelope>.Continuation!
        let stream = AsyncStream<EventPipelineEnvelope>(
            bufferingPolicy: .bufferingNewest(2)
        ) { continuation = $0 }
        continuation.finish()

        let telemetry = EventPipelineTelemetry()
        let event = makeEvent(category: .network, action: "connect", pid: 20)
        telemetry.yield(
            EventPipelineEnvelope(source: .network, event: event),
            to: continuation,
            lane: .priority
        )
        let snapshot = telemetry.snapshot()

        #expect(snapshot.offeredBySource["NetworkCollector"] == 1)
        #expect(snapshot.mergedTerminatedBySourceAndLane["NetworkCollector"]?["priority"] == 1)
        #expect(snapshot.backlogEstimateByLane["priority"] == 0)
        #expect(snapshot.detectionInputDroppedTotal == 1)
        _ = stream
    }

    @Test("concurrent real yields retain exact fixed-cardinality totals")
    func concurrentOverflowAccounting() {
        var continuation: AsyncStream<EventPipelineEnvelope>.Continuation!
        let stream = AsyncStream<EventPipelineEnvelope>(
            bufferingPolicy: .bufferingNewest(100)
        ) { continuation = $0 }
        let telemetry = EventPipelineTelemetry()
        let event = makeEvent(category: .process, action: "exec", pid: 30)
        let boundedContinuation = continuation!

        DispatchQueue.concurrentPerform(iterations: 1_000) { index in
            let source: EventPipelineSource = index.isMultiple(of: 2)
                ? .endpointSecurity : .unifiedLog
            telemetry.yield(
                EventPipelineEnvelope(source: source, event: event),
                to: boundedContinuation,
                lane: .priority
            )
        }
        let snapshot = telemetry.snapshot()
        let mergedDrops = snapshot.mergedDroppedBySourceAndLane.values.reduce(UInt64(0)) {
            $0 + $1.values.reduce(UInt64(0), +)
        }

        #expect(snapshot.offeredByLane["priority"] == 1_000)
        #expect(mergedDrops == 900)
        #expect(snapshot.mergedDroppedByLane["priority"] == 900)
        #expect(snapshot.backlogEstimateByLane["priority"] == 100)
        #expect(snapshot.detectionInputDroppedTotal == 900)
        _ = stream
    }

    @Test("every production source driver carries a bounded stable source tag")
    func productionDriveSourcesAreEnumerated() throws {
        let testFile = URL(fileURLWithPath: #filePath)
        let repositoryRoot = testFile
            .deletingLastPathComponent() // MacCrabCoreTests
            .deletingLastPathComponent() // Tests
            .deletingLastPathComponent() // repository
        let source = try String(
            contentsOf: repositoryRoot.appendingPathComponent(
                "Sources/MacCrabAgentKit/DaemonState.swift"
            ),
            encoding: .utf8
        )

        let stableTags = [
            ".endpointSecurity",
            ".kdebug",
            ".eslogger",
            ".unifiedLog",
            ".tcc",
            ".network",
        ]
        for tag in stableTags {
            #expect(source.contains("driveSource(\(tag)"), "missing stable source tag \(tag)")
        }

        // Six production invocations plus the single function declaration.
        #expect(source.components(separatedBy: "driveSource(").count - 1 == 7)
        #expect(source.contains("EventPipelineEnvelope(source: source, event: event)"))
        #expect(source.contains("pipelineTelemetry.yield(envelope, to: fCont, lane: lane)"))
        #expect(source.contains("pipelineTelemetry.yield(envelope, to: pCont, lane: lane)"))

        let telemetrySource = try String(
            contentsOf: repositoryRoot.appendingPathComponent(
                "Sources/MacCrabAgentKit/EventPipelineTelemetry.swift"
            ),
            encoding: .utf8
        )
        #expect(telemetrySource.contains("case .dropped(let oldEnvelope)"))
        #expect(telemetrySource.contains("oldEnvelope.source.rawValue"))
        #expect(telemetrySource.contains("finalLane(for: oldEnvelope.event)"),
                "buffer eviction must use the old event's final lane")
    }

    @Test("all six collector event buffers share the same exact yield instrumentation")
    func collectorBufferInventory() throws {
        let testFile = URL(fileURLWithPath: #filePath)
        let repositoryRoot = testFile
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let files = [
            "ESCollector.swift",
            "KdebugCollector.swift",
            "EsloggerCollector.swift",
            "UnifiedLogCollector.swift",
            "TCCMonitor.swift",
            "NetworkCollector.swift",
        ]

        for file in files {
            let source = try String(
                contentsOf: repositoryRoot
                    .appendingPathComponent("Sources/MacCrabCore/Collectors")
                    .appendingPathComponent(file),
                encoding: .utf8
            )
            #expect(source.contains(".bufferingNewest("), "\(file) lost its bounded stream")
            #expect(source.contains("deliveryCounters"), "\(file) is absent from heartbeat inventory")
            #expect(source.contains("deliveryTelemetry.recordYield(offered: event, result: result)"),
                    "\(file) does not inspect the actual AsyncStream yield result")
        }
    }

    @Test("each production consumer keeps its matching telemetry lane")
    func productionConsumersKeepLaneIdentity() throws {
        let testFile = URL(fileURLWithPath: #filePath)
        let repositoryRoot = testFile
            .deletingLastPathComponent() // MacCrabCoreTests
            .deletingLastPathComponent() // Tests
            .deletingLastPathComponent() // repository
        let source = try String(
            contentsOf: repositoryRoot.appendingPathComponent(
                "Sources/MacCrabAgentKit/DaemonBootstrap.swift"
            ),
            encoding: .utf8
        )

        func matchCount(_ pattern: String) throws -> Int {
            let regex = try NSRegularExpression(pattern: pattern)
            return regex.numberOfMatches(
                in: source,
                range: NSRange(source.startIndex..., in: source)
            )
        }

        let priorityMapping = #"EventLoop\.run\(\s*state: handles\.state,\s*lane: \.priority,\s*eventStream: streams\.priority,"#
        let fileMapping = #"EventLoop\.run\(\s*state: handles\.state,\s*lane: \.file,\s*eventStream: streams\.file,"#
        #expect(try matchCount(priorityMapping) == 1)
        #expect(try matchCount(fileMapping) == 1)
        #expect(source.components(separatedBy: "lane: .priority").count - 1 == 1)
        #expect(source.components(separatedBy: "lane: .file").count - 1 == 1)
        #expect(source.components(separatedBy: "EventLoop.run(").count - 1 == 2)

        let eventLoopSource = try String(
            contentsOf: repositoryRoot.appendingPathComponent(
                "Sources/MacCrabAgentKit/EventLoop.swift"
            ),
            encoding: .utf8
        )
        #expect(eventLoopSource.components(
            separatedBy: "recordRuleEvaluationReached("
        ).count - 1 == 1, "the event-level reached mark must not double count")
        #expect(eventLoopSource.components(
            separatedBy: "recordRuleEvaluationCompleted("
        ).count - 1 == 1, "the event-level completed mark must not double count")

        let reached = try #require(eventLoopSource.range(
            of: "recordRuleEvaluationReached("
        ))
        let singleRules = try #require(eventLoopSource.range(
            of: "state.ruleEngine.evaluate(enrichedEvent)"
        ))
        let sequenceRules = try #require(eventLoopSource.range(
            of: "state.sequenceEngine.evaluate(enrichedEvent)"
        ))
        let completed = try #require(eventLoopSource.range(
            of: "recordRuleEvaluationCompleted("
        ))
        #expect(reached.lowerBound < singleRules.lowerBound)
        #expect(singleRules.lowerBound < sequenceRules.lowerBound)
        #expect(sequenceRules.lowerBound < completed.lowerBound)
    }

    private func makeEvent(
        category: EventCategory,
        action: String,
        pid: Int32
    ) -> Event {
        let process = MacCrabCore.ProcessInfo(
            pid: pid,
            ppid: 1,
            rpid: 1,
            name: "probe",
            executable: "/usr/bin/true",
            commandLine: "/usr/bin/true",
            args: ["/usr/bin/true"],
            workingDirectory: "/tmp",
            userId: 501,
            userName: "probe",
            groupId: 20,
            startTime: Date(timeIntervalSince1970: 1)
        )
        return Event(
            eventCategory: category,
            eventType: .start,
            eventAction: action,
            process: process
        )
    }
}
