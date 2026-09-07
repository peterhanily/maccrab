import Foundation
import Testing
@testable import MacCrabCore

@Suite("TraceGraph live persistence age")
struct TraceGraphWriteHealthTests {
    private final class Clock: @unchecked Sendable {
        private let lock = NSLock()
        private var instant = ContinuousClock.now
        func now() -> ContinuousClock.Instant {
            lock.lock(); defer { lock.unlock() }
            return instant
        }
        func advance(_ seconds: Double) {
            lock.lock(); defer { lock.unlock() }
            instant = instant.advanced(by: .seconds(seconds))
        }
    }

    private enum PlannedFailure: Error { case write }

    private actor WriteGate {
        private var first = true
        private var paused = false
        private var release: CheckedContinuation<Void, Never>?
        private var observers: [CheckedContinuation<Void, Never>] = []
        let failFirst: Bool
        init(failFirst: Bool = false) { self.failFirst = failFirst }
        func enter() async throws {
            guard first else { return }
            first = false
            await withCheckedContinuation { continuation in
                release = continuation
                paused = true
                observers.forEach { $0.resume() }
                observers.removeAll()
            }
            if failFirst { throw PlannedFailure.write }
        }
        func waitUntilPaused() async {
            if paused { return }
            await withCheckedContinuation { observers.append($0) }
        }
        func open() { release?.resume(); release = nil }
    }

    // Long scheduling delay keeps these tests independent of wall time. Every
    // commit boundary is explicitly driven; production still uses 250 ms.
    private let policy = CausalGraphIngestionWritePolicy(
        maximumDelaySeconds: 3_600, maximumPendingEvents: 256, maximumPendingRows: 1_024
    )

    private func event(_ id: String, date: Date = .distantPast) -> RollingCausalGraph.NormalizedEventInput {
        .init(
            eventId: id, timestamp: date, category: .process, action: .exec,
            process: .init(
                processKey: "ordinary-process", pid: 100, ppid: 1,
                executablePath: "/usr/bin/true", isAppleSigned: true,
                isNotarized: true, startTime: date
            )
        )
    }

    @Test("Coalescing age keeps the first enqueue time and clears after commit")
    func normalPendingAndNewGeneration() async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = try await SQLiteCausalGraphStore(databasePath: directory.appendingPathComponent("graph.db").path)
        let clock = Clock()
        let graph = RollingCausalGraph(
            store: store, materializer: TraceMaterializer(store: store),
            ingestionWritePolicy: policy, monotonicNow: { clock.now() },
            persistBatch: { try await store.upsertBatch(entities: $0, edges: $1) }
        )
        _ = try await graph.ingest(event("first"))
        #expect((await graph.writeTelemetry()).oldestOutstandingAgeSeconds == 0)
        clock.advance(0.125)
        // Even an unrelated wall/event time must not refresh the first age.
        _ = try await graph.ingest(event("second", date: .distantFuture))
        clock.advance(0.125)
        let pending = await graph.writeTelemetry()
        #expect(pending.eventsPending == 2)
        #expect(pending.oldestOutstandingAgeSeconds == 0.25)
        try await graph.flushPending()
        let settled = await graph.writeTelemetry()
        #expect(settled.eventsCommittedTotal == 2)
        #expect(settled.eventsPending == 0)
        #expect(settled.oldestOutstandingAgeSeconds == 0)
        clock.advance(100)
        _ = try await graph.ingest(event("fresh"))
        #expect((await graph.writeTelemetry()).oldestOutstandingAgeSeconds == 0)
        try await graph.flushPending()
        await store.close()
    }

    @Test("In-flight age survives handoff and old completion preserves newer pending age", arguments: [false, true])
    func overlappingBatches(failFirst: Bool) async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = try await SQLiteCausalGraphStore(databasePath: directory.appendingPathComponent("graph.db").path)
        let clock = Clock()
        let gate = WriteGate(failFirst: failFirst)
        let graph = RollingCausalGraph(
            store: store, materializer: TraceMaterializer(store: store),
            ingestionWritePolicy: policy, monotonicNow: { clock.now() },
            persistBatch: { entities, edges in
                try await gate.enter()
                try await store.upsertBatch(entities: entities, edges: edges)
            }
        )
        _ = try await graph.ingest(event("older"))
        clock.advance(0.25)
        let flush = Task { try await graph.flushPending() }
        await gate.waitUntilPaused()
        clock.advance(12)
        let inFlight = await graph.writeTelemetry()
        #expect(inFlight.eventsPending == 0)
        #expect(inFlight.eventsInFlight == 1)
        #expect(inFlight.oldestOutstandingAgeSeconds == 12.25)
        _ = try await graph.ingest(event("newer"))
        clock.advance(3)
        #expect((await graph.writeTelemetry()).oldestOutstandingAgeSeconds == 15.25)
        await gate.open()
        if failFirst {
            await #expect(throws: PlannedFailure.self) { try await flush.value }
        } else {
            try await flush.value
        }
        let newer = await graph.writeTelemetry()
        #expect(newer.eventsInFlight == 0)
        #expect(newer.eventsPending == 1)
        #expect(newer.oldestOutstandingAgeSeconds == 3)
        #expect(newer.eventsFailedTotal == (failFirst ? 1 : 0))
        try await graph.flushPending()
        let completed = await graph.writeTelemetry()
        #expect(completed.oldestOutstandingAgeSeconds == 0)
        #expect(completed.eventsCommittedTotal == (failFirst ? 1 : 2))
        #expect(completed.eventsFailedTotal == (failFirst ? 1 : 0))
        #expect(completed.inputEventsTotal == completed.eventsCommittedTotal + completed.eventsFailedTotal)
        // A new writer generation starts a new ledger, not the prior age/failure.
        let restarted = RollingCausalGraph(store: store, materializer: TraceMaterializer(store: store))
        let fresh = await restarted.writeTelemetry()
        #expect(fresh.oldestOutstandingAgeSeconds == 0)
        #expect(fresh.eventsFailedTotal == 0)
        await store.close()
    }

    private func status(
        pending: Int = 1, inFlight: Int = 0, committed: Int = 0, failed: Int = 0,
        age: Any? = 0, omissions: [String] = []
    ) throws -> HeartbeatSnapshot.TraceGraphStorageAdmission {
        var raw: [String: Any] = [
            "enabled": true, "blocked": false, "store_available": true,
            "ingest_events_total": pending + inFlight + committed + failed,
            "ingest_events_committed_total": committed, "ingest_events_failed_total": failed,
            "ingest_events_in_flight": inFlight, "ingest_events_pending": pending,
            "entity_observations_total": pending + inFlight + committed + failed,
            "edge_observations_total": 0,
            "relevance_suppressed_file_events_total": 0, "relevance_suppressed_rows_total": 0,
            "write_attempts_total": inFlight + committed + failed,
            "write_batches_committed_total": committed, "write_batches_failed_total": failed,
            "write_batches_in_flight": inFlight,
            "write_rows_attempted_total": inFlight + committed + failed,
            "write_rows_committed_total": committed, "write_rows_failed_total": failed,
            "write_rows_in_flight": inFlight, "coalesced_noop_rows_total": 0,
            "pending_entity_rows": pending, "pending_edge_rows": 0,
        ]
        if let age { raw["oldest_outstanding_age_seconds"] = age }
        for key in omissions { raw.removeValue(forKey: key) }
        let decoder = JSONDecoder()
        decoder.nonConformingFloatDecodingStrategy = .convertFromString(
            positiveInfinity: "Infinity", negativeInfinity: "-Infinity", nan: "NaN"
        )
        return try decoder.decode(
            HeartbeatSnapshot.TraceGraphStorageAdmission.self,
            from: JSONSerialization.data(withJSONObject: raw)
        )
    }

    @Test("Normal queue and active write stay healthy through the explicit live deadline")
    func healthyPendingDeadline() throws {
        for age in [0, 0.125, 0.25, 10.25] {
            for inFlight in [0, 1] {
                let value = try status(pending: 1 - inFlight, inFlight: inFlight, age: age)
                #expect(value.writeConservationMaintained == true)
                #expect(value.hasOutstandingBacklog == false)
                #expect(!value.graphWriteDegraded)
            }
        }
        for inFlight in [0, 1] {
            let stalled = try status(pending: 1 - inFlight, inFlight: inFlight, age: 10.251)
            #expect(stalled.hasOutstandingBacklog == true)
            #expect(stalled.graphWriteDegraded)
        }
        let recovered = try status(pending: 0, committed: 1, age: 0)
        #expect(!recovered.graphWriteDegraded)
        let failed = try status(pending: 0, committed: 1, failed: 1, age: 0)
        #expect(failed.writeConservationMaintained == true)
        #expect(failed.hasOutstandingBacklog == false)
        #expect(failed.graphWriteDegraded)
    }

    @Test("Missing and invalid timing cannot make outstanding work healthy")
    func unknownAndCorruptTiming() throws {
        let invalid: [Any?] = [nil, -0.01, "NaN", "Infinity", "-Infinity"]
        for age in invalid {
            for inFlight in [0, 1] {
                let value = try status(pending: 1 - inFlight, inFlight: inFlight, age: age)
                #expect(value.hasOutstandingBacklog == nil)
                #expect(value.graphWriteDegraded)
            }
        }
        let idleLegacy = try status(pending: 0, age: nil)
        #expect(!idleLegacy.graphWriteDegraded)
        let inconsistentIdleAges: [Any] = [0.1, -1.0, "NaN"]
        for age in inconsistentIdleAges {
            let inconsistent = try status(pending: 0, age: age)
            #expect(inconsistent.graphWriteDegraded)
        }
        let negative = try status(pending: -1, age: 0)
        #expect(negative.graphWriteDegraded)
        let partial = try status(age: 0, omissions: ["write_batches_committed_total"])
        #expect(partial.graphWriteDegraded)
        let drift = try status(age: 0, omissions: ["pending_entity_rows"])
        #expect(drift.graphWriteDegraded)
    }
}
