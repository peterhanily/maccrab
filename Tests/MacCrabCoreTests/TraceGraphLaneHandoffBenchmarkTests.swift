// TraceGraphLaneHandoffBenchmarkTests.swift
// v1.22.7 lane-tracegraph — deterministic, in-process measurement of how
// long the detection lane spends handing an enriched event to TraceGraph
// when the graph store is slow. No sleeps: the slow store burns a fixed,
// bounded amount of CPU per physical batch, so the numbers are comparable
// between the inline (pre-v1.22.7) hand-off and the bounded ingest queue.

import CryptoKit
import Foundation
import Testing
@testable import MacCrabCore

/// Deterministic store cost: SHA-256 over a fixed buffer. One call is bounded
/// CPU work with no timers, so a benchmark built on it has a finite runtime
/// on any host and never sleeps.
enum TraceGraphBenchmarkSlowStore {
    private static let block = Data(repeating: 0xA5, count: 1 << 20)

    static func burn(mebibytes: Int) {
        var hasher = SHA256()
        for _ in 0..<mebibytes { hasher.update(data: block) }
        _ = hasher.finalize()
    }
}

@Suite("TraceGraph lane hand-off benchmark", .serialized)
struct TraceGraphLaneHandoffBenchmarkTests {

    static let eventCount = 2_048
    /// ~64 MiB of SHA-256 per physical batch: tens of milliseconds, so a
    /// daemon-coalesced batch of 256 events caps an inline lane well below
    /// the hand-off rate the lane itself can sustain.
    static let storeMebibytesPerBatch = 64

    private let now = Date(timeIntervalSince1970: 1_700_000_000)

    private func makeStore() async throws -> (SQLiteCausalGraphStore, URL) {
        let path = FileManager.default.temporaryDirectory
            .appendingPathComponent("lane-bench-\(UUID().uuidString).db")
        return (try await SQLiteCausalGraphStore(databasePath: path.path), path)
    }

    private func removeStore(at path: URL) {
        for suffix in ["", "-wal", "-shm", "-journal"] {
            try? FileManager.default.removeItem(atPath: path.path + suffix)
        }
    }

    private func execEvent(_ index: Int) -> Event {
        Event(
            timestamp: now.addingTimeInterval(Double(index) / 1_000),
            eventCategory: .process,
            eventType: .start,
            eventAction: "exec",
            process: MacCrabCore.ProcessInfo(
                pid: Int32(index + 1), ppid: 1, rpid: Int32(index + 1),
                name: "true",
                executable: "/usr/bin/true",
                commandLine: "/usr/bin/true",
                args: [], workingDirectory: "/",
                userId: 501, userName: "bench", groupId: 20,
                startTime: now,
                codeSignature: CodeSignatureInfo(signerType: .apple, isNotarized: true),
                isPlatformBinary: true
            ),
            enrichments: [
                EventToRollingCausalGraphBridge.processKeyEnrichmentKey:
                    "lane-bench-process-\(index)"
            ]
        )
    }

    private func makeSlowGraph(
        store: SQLiteCausalGraphStore
    ) -> RollingCausalGraph {
        let mebibytes = Self.storeMebibytesPerBatch
        return RollingCausalGraph(
            store: store,
            materializer: TraceMaterializer(store: store),
            ingestionWritePolicy: .daemonCoalesced,
            monotonicNow: { ContinuousClock.now },
            persistBatch: { entities, edges in
                TraceGraphBenchmarkSlowStore.burn(mebibytes: mebibytes)
                try await store.upsertBatch(entities: entities, edges: edges)
            }
        )
    }

    private static func eventsPerSecond(_ count: Int, _ elapsed: Duration) -> Double {
        let seconds = Double(elapsed.components.seconds)
            + Double(elapsed.components.attoseconds) / 1e18
        return seconds > 0 ? Double(count) / seconds : .infinity
    }

    /// BEFORE (v1.22.6 lane shape): the lane awaits `bridge.process` inline, so
    /// every coalesced flush and every store transaction is paid on the lane.
    @Test("baseline: inline bridge.process hand-off is bounded by store speed")
    func inlineHandoffIsStoreBound() async throws {
        let (store, dbPath) = try await makeStore()
        defer { removeStore(at: dbPath) }
        let graph = makeSlowGraph(store: store)
        let bridge = EventToRollingCausalGraphBridge(rollingGraph: graph)
        let events = (0..<Self.eventCount).map(execEvent)

        let start = ContinuousClock.now
        for event in events {
            _ = await bridge.process(event)
        }
        let laneElapsed = start.duration(to: .now)
        try await bridge.flushPending()
        let totalElapsed = start.duration(to: .now)

        let telemetry = await bridge.writeTelemetry()
        #expect(telemetry.inputEventsTotal == UInt64(Self.eventCount))
        #expect(telemetry.eventsCommittedTotal == UInt64(Self.eventCount))
        #expect(telemetry.eventsFailedTotal == 0)
        print("[lane-bench] before/inline: \(Self.eventCount) events, lane \(laneElapsed), total \(totalElapsed), lane \(Int(Self.eventsPerSecond(Self.eventCount, laneElapsed))) ev/s")
        await store.close()
    }

    /// AFTER (v1.22.7): the lane hands off to the bounded ingest queue and
    /// returns; the service task pays the store cost. Within capacity nothing
    /// is dropped, so the comparison is like for like: every event commits.
    @Test("bounded queue hand-off is independent of store speed and drops nothing within capacity")
    func queuedHandoffIsStoreIndependent() async throws {
        let (store, dbPath) = try await makeStore()
        defer { removeStore(at: dbPath) }
        let graph = makeSlowGraph(store: store)
        let bridge = EventToRollingCausalGraphBridge(rollingGraph: graph)
        #expect(bridge.ingestQueueCapacity >= Self.eventCount)
        let events = (0..<Self.eventCount).map(execEvent)
        let service = Task { await bridge.runIngestService { _, _ in } }

        let start = ContinuousClock.now
        for event in events {
            bridge.offer(event)
        }
        let laneElapsed = start.duration(to: .now)
        bridge.finishIngestQueue()
        await service.value
        try await bridge.flushPending()
        let totalElapsed = start.duration(to: .now)

        let queue = bridge.ingestQueueTelemetry()
        #expect(queue.handoffsTotal == UInt64(Self.eventCount))
        #expect(queue.droppedTotal == 0)
        #expect(queue.latchedShedTotal == 0)
        #expect(queue.completedTotal == UInt64(Self.eventCount))
        #expect(queue.backlog == 0)
        let telemetry = await bridge.writeTelemetry()
        #expect(telemetry.inputEventsTotal == UInt64(Self.eventCount))
        #expect(telemetry.eventsCommittedTotal == UInt64(Self.eventCount))
        #expect(telemetry.eventsFailedTotal == 0)

        let laneRate = Self.eventsPerSecond(Self.eventCount, laneElapsed)
        // Throughput floor: the hand-off is a schema check, one lock, one
        // bounded yield. 10k events/s is two orders of magnitude under the
        // measured rate, so a loaded CI host still passes; a lane that waited
        // on even one slow batch (tens of ms per 256 events) could not.
        #expect(laneRate >= 10_000, "lane hand-off rate \(Int(laneRate)) ev/s fell below the floor")
        print("[lane-bench] after/queued: \(Self.eventCount) events, lane \(laneElapsed), total \(totalElapsed), lane \(Int(laneRate)) ev/s")
        await store.close()
    }
}
