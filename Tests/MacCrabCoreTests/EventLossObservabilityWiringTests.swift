import Foundation
import Testing

@Suite("Event-loss observability wiring")
struct EventLossObservabilityWiringTests {
    private var repositoryRoot: URL {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
    }

    private func source(_ relativePath: String) throws -> String {
        try String(
            contentsOf: repositoryRoot.appendingPathComponent(relativePath),
            encoding: .utf8
        )
    }

    private func occurrences(of needle: String, in source: String) -> Int {
        source.components(separatedBy: needle).count - 1
    }

    @Test("both heartbeat surfaces carry the same process-epoch identity")
    func heartbeatIdentityDoesNotDrift() throws {
        let timers = try source("Sources/MacCrabAgentKit/DaemonTimers.swift")
        for key in [
            "engine_pid",
            "engine_started_at_unix",
            "engine_version",
            "engine_build",
        ] {
            #expect(occurrences(of: "\"\(key)\": engineIdentity.", in: timers) == 2,
                    "\(key) must be written once to liveness and once to rich heartbeat")
        }

        let setup = try source("Sources/MacCrabAgentKit/DaemonSetup.swift")
        #expect(setup.contains("static let current = DaemonProcessIdentity("))
        #expect(setup.contains("\"engine_pid\": identity.pid"),
                "boot-phase heartbeat must use the same process epoch")
        #expect(setup.contains("\"engine_started_at_unix\": identity.startedAtUnix"))
    }

    @Test("ES policy and normalization maps reach the rich heartbeat")
    func esStageLedgerWiringDoesNotDrift() throws {
        let collector = try source("Sources/MacCrabCore/Collectors/ESCollector.swift")
        #expect(collector.contains("esIntentionallyFilteredBeforeWorkerByType()"))
        #expect(collector.contains("esNormalizedYieldedByType()"))

        let timers = try source("Sources/MacCrabAgentKit/DaemonTimers.swift")
        #expect(timers.contains(
            "\"es_intentionally_filtered_before_worker_by_type\": esIntentionallyFilteredBeforeWorkerByType"
        ))
        #expect(timers.contains(
            "\"es_normalized_yielded_by_type\": esNormalizedYieldedByType"
        ))
    }

    @Test("rule boundary and storage ledger are emitted without changing legacy drops")
    func ruleAndStorageWiringDoesNotDrift() throws {
        let timers = try source("Sources/MacCrabAgentKit/DaemonTimers.swift")
        #expect(timers.contains(
            "\"rule_evaluation_reached_by_lane_and_category\": eventPipeline.ruleEvaluationReachedByLaneAndCategory"
        ))
        #expect(timers.contains(
            "\"rule_evaluation_completed_by_lane_and_category\": eventPipeline.ruleEvaluationCompletedByLaneAndCategory"
        ))
        #expect(timers.contains(
            "let eventWriterTelemetry = await state.eventWriter.telemetrySnapshot()"
        ))
        #expect(timers.contains(
            "let eventInsertFilterCounters = await state.eventStore.insertFilterCounters()"
        ))
        #expect(timers.contains(
            "\"events_storage_write_dropped_total\": eventWriterTelemetry.droppedCount"
        ), "legacy storage-drop meaning must remain the writer's permanent sheds")
        #expect(timers.contains(
            "\"events_storage_write_persisted_total\": eventWriterTelemetry.persistedCount"
        ))
        #expect(timers.contains(
            "\"events_storage_write_retried_total\": eventWriterTelemetry.retriedCount"
        ))
        #expect(timers.contains(
            "\"events_storage_write_buffer_depth\": eventWriterTelemetry.bufferDepth"
        ))
        #expect(timers.contains(
            "\"events_storage_write_in_flight_depth\": eventWriterTelemetry.inFlightDepth"
        ))
        #expect(timers.contains(
            "payload[\"events_insert_filter_dropped_total\"] = eventInsertFilterCounters.dropped"
        ))
        #expect(timers.contains(
            "payload[\"events_insert_filter_passed_total\"] = eventInsertFilterCounters.passed"
        ))
    }
}
