import Foundation
import Testing
@testable import MacCrabApp
@testable import MacCrabCore

@Suite("Dashboard event reads during engine startup", .serialized)
struct EventReadStartupTests {
    private func heartbeat(phase: String, now: Date) -> [String: Any] {
        ["engine_pid": 101, "engine_started_at_unix": now.addingTimeInterval(-5).timeIntervalSince1970,
         "engine_version": "1.22.0", "engine_build": "test", "boot_phase": phase,
         "written_at_unix": now.timeIntervalSince1970, "liveness": phase == "ready"]
    }

    @Test("Only fresh identified startup telemetry defers reads")
    func startupPolicy() throws {
        let now = Date(timeIntervalSince1970: 1_780_000_000)
        let identity = try #require(EngineTelemetryIdentity(heartbeat: heartbeat(phase: "starting", now: now)))
        for phase in ["starting", "upgrading_store", "stores_ready", "rules_loaded", "collectors_started"] {
            #expect(V2EngineSource.defersEventReads(phase: phase, writtenAt: now,
                identity: identity, now: now))
        }
        for phase in ["ready", "failed", "future_phase", ""] {
            #expect(!V2EngineSource.defersEventReads(phase: phase, writtenAt: now,
                identity: identity, now: now))
        }
        for offset in [-121.0, 1.0] {
            #expect(!V2EngineSource.defersEventReads(phase: "starting",
                writtenAt: now.addingTimeInterval(offset), identity: identity, now: now))
        }
        #expect(!V2EngineSource.defersEventReads(phase: "starting", writtenAt: nil,
            identity: identity, now: now))
        #expect(!V2EngineSource.defersEventReads(phase: "starting", writtenAt: now,
            identity: nil, now: now))
    }

    @Test("Startup retires old handles and ready telemetry reopens the selected source")
    @MainActor
    func startupAndRecovery() async throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrab-ui-startup-\(UUID())")
        defer { try? FileManager.default.removeItem(at: directory) }
        let writer = try EventStore(directory: directory.path)
        let alertWriter = try AlertStore(directory: directory.path)
        defer { withExtendedLifetime(alertWriter) {} }
        let source = V2EngineSource(directory: directory.path)
        let path = directory.appendingPathComponent("heartbeat.json")
        func write(_ phase: String) throws {
            try JSONSerialization.data(withJSONObject: heartbeat(phase: phase, now: Date()))
                .write(to: path, options: .atomic)
        }
        try write("ready")
        let app = AppState(engineSource: source, startBackgroundWork: false)
        app.refreshHeartbeat()
        let reader = try EventStore(directory: directory.path, forceReadOnly: true)
        app.primeCachedEventStoreForTesting(reader)
        let oldProvider = try #require(await V2LiveDataProvider(source: source))
        #expect(oldProvider.lastErrorDescription == nil, "Both mandatory fixture stores must open before startup")
        try write("upgrading_store")
        app.refreshHeartbeat()
        #expect(app.eventReadsDeferred)
        #expect(!app.hasCachedEventStoreForTesting)
        #expect(await V2LiveDataProvider(source: source) == nil)
        #expect(await oldProvider.events(limit: 10).isEmpty)
        #expect(oldProvider.lastErrorDescription == nil)
        await app.loadEvents(filter: "fixture")
        _ = await app.fetchAggregates(sinceDay: "2026-01-01")
        #expect(app.eventSearchCoverageWarning == nil)
        #expect(app.eventAggregateCoverageWarning == nil)
        do {
            _ = try await reader.exactEventsSnapshot(since: .distantPast)
            Issue.record("Startup did not retire the previously cached reader")
        } catch is CancellationError { }
        try FileManager.default.removeItem(at: path)
        app.refreshHeartbeat()
        #expect(!app.eventReadsDeferred, "Missing startup telemetry must permit historical reads")
        try write("starting")
        app.refreshHeartbeat()
        #expect(app.eventReadsDeferred)
        try write("ready")
        app.refreshHeartbeat()
        #expect(!app.eventReadsDeferred)
        await app.loadEvents()
        #expect(app.hasCachedEventStoreForTesting)
        #expect(await V2LiveDataProvider(source: source) != nil)
        app.stopPolling()
        #expect(await writer.walCheckpointTruncate())
    }

    @Test("Unreadable durability blocks cannot report healthy")
    @MainActor
    func unreadableDurability() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrab-ui-durability-\(UUID())")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let malformed: [(Any, Any)] = [
            ("unreadable", "unreadable"),
            (["ingest_events_total": "invalid"], ["capture_pending": "invalid"]),
        ]
        for (graph, budget) in malformed {
            var raw = heartbeat(phase: "ready", now: Date())
            raw["tracegraph_storage_admission"] = graph
            raw["alert_evidence_budget"] = budget
            try JSONSerialization.data(withJSONObject: raw)
                .write(to: directory.appendingPathComponent("heartbeat.json"), options: .atomic)
            let app = AppState(engineSource: .init(directory: directory.path), startBackgroundWork: false)
            app.refreshHeartbeat()
            #expect(app.heartbeat?.alertEvidenceBudgetDegraded == true)
            #expect(app.heartbeat?.traceGraphWriteDegraded == true)
        }
    }
}
