// AgentLineageServiceTests.swift
//
// Coverage for the v1.6.6 Agent Data Lineage service: session
// lifecycle, ring-buffer eviction, chronological ordering, and
// cross-event-kind timeline assembly.

import Testing
import Foundation
@testable import MacCrabCore

private final class LineageSnapshotPersistenceProbe: @unchecked Sendable {
    private let lock = NSLock()
    private let firstEntered = DispatchSemaphore(value: 0)
    private let releaseFirst = DispatchSemaphore(value: 0)
    private var invocationCount = 0
    private var persistedEventCounts: [Int] = []

    func persist(
        snapshot: AgentLineageService.LineageSnapshot,
        path _: String
    ) -> String? {
        lock.lock()
        let invocation = invocationCount
        invocationCount += 1
        lock.unlock()

        if invocation == 0 {
            firstEntered.signal()
            releaseFirst.wait()
        }

        lock.lock()
        persistedEventCounts.append(snapshot.sessions.reduce(0) { $0 + $1.events.count })
        lock.unlock()
        return nil
    }

    func waitUntilFirstEntered(timeout: TimeInterval = 30) async -> Bool {
        let semaphore = firstEntered
        return await Task.detached {
            semaphore.wait(timeout: .now() + timeout) == .success
        }.value
    }

    func releaseFirstWrite() {
        releaseFirst.signal()
    }

    func eventCounts() -> [Int] {
        lock.lock()
        defer { lock.unlock() }
        return persistedEventCounts
    }
}

@Suite("AgentLineageService: session lifecycle")
struct AgentLineageLifecycleTests {

    @Test("Recording on an unstarted PID is a silent no-op")
    func recordWithoutStartIsDropped() async {
        let svc = AgentLineageService()
        await svc.record(aiPid: 1234, kind: .fileRead(path: "/tmp/x"))
        let snap = await svc.snapshot(aiPid: 1234)
        #expect(snap == nil)
    }

    @Test("Start session creates an empty timeline")
    func startCreatesEmptyTimeline() async {
        let svc = AgentLineageService()
        await svc.startSession(aiPid: 42, toolType: .claudeCode, projectDir: "/Users/x/proj")
        let snap = await svc.snapshot(aiPid: 42)
        #expect(snap?.aiPid == 42)
        #expect(snap?.eventCount == 0)
        #expect(snap?.projectDir == "/Users/x/proj")
    }

    @Test("End session removes it from allSessions")
    func endRemoves() async {
        let svc = AgentLineageService()
        await svc.startSession(aiPid: 1, toolType: .cursor, projectDir: nil)
        await svc.endSession(aiPid: 1)
        #expect(await svc.snapshot(aiPid: 1) == nil)
        #expect(await svc.allSessions().isEmpty)
    }

    @Test("Duplicate startSession is a no-op (preserves existing timeline)")
    func duplicateStartPreservesTimeline() async {
        let svc = AgentLineageService()
        await svc.startSession(aiPid: 7, toolType: .cursor, projectDir: "/a")
        await svc.record(aiPid: 7, kind: .fileRead(path: "/f1"))
        await svc.startSession(aiPid: 7, toolType: .cursor, projectDir: "/b")  // should no-op
        let snap = await svc.snapshot(aiPid: 7)
        #expect(snap?.eventCount == 1)
        #expect(snap?.projectDir == "/a", "Duplicate start must not clobber projectDir")
    }
}

@Suite("AgentLineageService: timeline assembly")
struct AgentLineageTimelineTests {

    @Test("file timeline materializes completed text context, not raw callback volume or credentials")
    func boundedFileMaterializationContract() {
        #expect(AgentLineageService.materializedFileEventKind(
            path: "/Users/test/project/README.md",
            eventAction: "open"
        ) == .fileRead(path: "/Users/test/project/README.md"))
        #expect(AgentLineageService.materializedFileEventKind(
            path: "/Users/test/project/main.swift",
            eventAction: "close_modified"
        ) == .fileWrite(path: "/Users/test/project/main.swift"))

        // Incomplete write callbacks cannot become a clean/scanned timeline
        // entry; the completed CLOSE is the canonical write observation.
        #expect(AgentLineageService.materializedFileEventKind(
            path: "/Users/test/project/main.swift",
            eventAction: "write"
        ) == nil)
        #expect(AgentLineageService.materializedFileEventKind(
            path: "/private/var/folders/hf/cache.bin",
            eventAction: "close_modified"
        ) == nil)
        #expect(AgentLineageService.materializedFileEventKind(
            path: "/Users/test/Documents/report.pdf",
            eventAction: "open"
        ) == nil)

        // The persisted lineage snapshot is not a credential-path side
        // channel, even though `.env` is otherwise a supported text file.
        #expect(AgentLineageService.materializedFileEventKind(
            path: "/Users/test/project/.env",
            eventAction: "open"
        ) == nil)
        #expect(AgentLineageService.materializedFileEventKind(
            path: "/Users/test/.aws/credentials",
            eventAction: "open"
        ) == nil)
        #expect(AgentLineageService.materializedFileEventKind(
            path: "/Users/test/.aws/sso/cache/session.json",
            eventAction: "open"
        ) == nil)
    }

    @Test("bounded lineage context still drives PromptIntentBridge")
    func boundedContextFeedsPromptIntent() async throws {
        let service = AgentLineageService()
        let pid: Int32 = 444
        let path = "/Users/test/project/README.md"
        let now = Date()
        await service.startSession(
            aiPid: pid,
            toolType: .claudeCode,
            projectDir: "/Users/test/project",
            startTime: now.addingTimeInterval(-30)
        )
        let kind = try #require(AgentLineageService.materializedFileEventKind(
            path: path,
            eventAction: "open"
        ))
        await service.record(
            aiPid: pid,
            kind: kind,
            timestamp: now.addingTimeInterval(-10)
        )

        let bridge = PromptIntentBridge(
            snapshotProvider: { requestedPID in
                await service.snapshot(aiPid: requestedPID)
            },
            fileReader: { requestedPath in
                requestedPath == path
                    ? "Install swift-argument-parser for command parsing."
                    : nil
            }
        )
        let result = await bridge.analyzeInstall(
            aiPid: pid,
            packageName: "swift-argument-parser",
            destructiveBlastRadius: 0
        )
        #expect(result.label == .userInitiated)
    }

    @Test("Events return in chronological order regardless of insert order")
    func chronologicalReassembly() async {
        let svc = AgentLineageService()
        let base = Date()
        await svc.startSession(aiPid: 100, toolType: .claudeCode, projectDir: nil, startTime: base)
        await svc.record(aiPid: 100, kind: .fileWrite(path: "/late"), timestamp: base.addingTimeInterval(30))
        await svc.record(aiPid: 100, kind: .llmCall(provider: "claude", endpoint: "/v1/messages", bytesUp: 1200, bytesDown: 4000), timestamp: base.addingTimeInterval(5))
        await svc.record(aiPid: 100, kind: .processSpawn(basename: "git", pid: 101), timestamp: base.addingTimeInterval(15))

        let snap = await svc.snapshot(aiPid: 100)!
        let times = snap.events.map(\.timestamp)
        #expect(times == times.sorted())
    }

    @Test("Kind counts correctly tally the full timeline")
    func kindCounts() async {
        let svc = AgentLineageService()
        let now = Date()
        await svc.startSession(aiPid: 200, toolType: .continuedev, projectDir: nil, startTime: now)
        await svc.record(aiPid: 200, kind: .llmCall(provider: "openai", endpoint: "/v1/chat/completions", bytesUp: 512, bytesDown: 2048))
        await svc.record(aiPid: 200, kind: .llmCall(provider: "openai", endpoint: "/v1/chat/completions", bytesUp: 512, bytesDown: 2048))
        await svc.record(aiPid: 200, kind: .fileRead(path: "/proj/a.ts"))
        await svc.record(aiPid: 200, kind: .fileWrite(path: "/proj/a.ts"))
        await svc.record(aiPid: 200, kind: .fileWrite(path: "/proj/b.ts"))
        await svc.record(aiPid: 200, kind: .network(host: "api.openai.com", port: 443))
        await svc.record(aiPid: 200, kind: .processSpawn(basename: "node", pid: 201))
        await svc.record(aiPid: 200, kind: .alert(ruleTitle: "Credential read detected", severity: .high))

        let snap = await svc.snapshot(aiPid: 200)!
        let counts = snap.kindCounts
        #expect(counts.llmCalls == 2)
        #expect(counts.reads == 1)
        #expect(counts.writes == 2)
        #expect(counts.networks == 1)
        #expect(counts.spawns == 1)
        #expect(counts.alerts == 1)
    }

    @Test("Windowed event query trims outside the bounds")
    func windowedQuery() async {
        let svc = AgentLineageService()
        let t0 = Date()
        await svc.startSession(aiPid: 300, toolType: .claudeCode, projectDir: nil, startTime: t0)
        for i in 0..<10 {
            await svc.record(aiPid: 300, kind: .fileRead(path: "/f\(i)"), timestamp: t0.addingTimeInterval(Double(i)))
        }
        let inside = await svc.events(aiPid: 300,
                                     since: t0.addingTimeInterval(3),
                                     until: t0.addingTimeInterval(6))
        #expect(inside.count == 4, "Seconds 3,4,5,6 inclusive → 4 events")
    }
    // APPCORE-03 regression: AppState.refreshAgentLineage() now performs
    // the Data-read + JSON decode inside a Task.detached and hops back to
    // @MainActor to publish. This pins the exact off-main call path —
    // readSnapshot is invoked from a detached task and its result (a
    // Sendable LineageSnapshot) must cross the actor boundary intact.
    @Test("readSnapshot crosses the actor boundary intact when called off-main (APPCORE-03)")
    func readSnapshotOffMainRoundTrip() async throws {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let session = AgentSessionSnapshot(
            aiPid: 4242,
            toolType: .claudeCode,
            projectDir: "/proj",
            startTime: now,
            events: [
                AgentEvent(timestamp: now.addingTimeInterval(1), kind: .fileRead(path: "/proj/a.ts")),
                AgentEvent(timestamp: now.addingTimeInterval(2), kind: .network(host: "api.anthropic.com", port: 443)),
            ]
        )
        let snap = AgentLineageService.LineageSnapshot(writtenAt: now, sessions: [session])
        let path = NSTemporaryDirectory() + "maccrab-lineage-offmain-\(UUID().uuidString).json"
        defer { try? FileManager.default.removeItem(atPath: path) }
        try JSONEncoder().encode(snap).write(to: URL(fileURLWithPath: path))

        // Read it back exactly the way refreshAgentLineage now does:
        // off the calling actor, returning a Sendable value to await.
        let loaded = await Task.detached(priority: .userInitiated) {
            AgentLineageService.readSnapshot(at: path)
        }.value

        #expect(loaded != nil)
        #expect(loaded?.sessions.count == 1)
        #expect(loaded?.sessions.first?.aiPid == 4242)
        #expect(loaded?.sessions.first?.events.count == 2)
    }
}

@Suite("AgentLineageService: capacity limits")
struct AgentLineageCapacityTests {

    @Test("Ring-buffer per session drops oldest events past the cap")
    func ringBufferDropsOldest() async {
        let svc = AgentLineageService(maxEventsPerSession: 5, maxSessions: 8)
        await svc.startSession(aiPid: 1, toolType: .cursor, projectDir: nil)
        let base = Date()
        for i in 0..<10 {
            await svc.record(aiPid: 1, kind: .fileRead(path: "/f\(i)"), timestamp: base.addingTimeInterval(Double(i)))
        }
        let snap = await svc.snapshot(aiPid: 1)!
        #expect(snap.events.count == 5)
        // Events 0..<5 were dropped; remaining should be 5..<10
        let paths = snap.events.compactMap { event -> String? in
            if case let .fileRead(path) = event.kind { return path }
            return nil
        }
        #expect(paths == ["/f5", "/f6", "/f7", "/f8", "/f9"])
    }

    @Test("Session-count cap evicts LRU when a new session starts")
    func sessionLRUEviction() async {
        let svc = AgentLineageService(maxEventsPerSession: 10, maxSessions: 2)
        let base = Date()
        await svc.startSession(aiPid: 1, toolType: .cursor, projectDir: nil, startTime: base)
        await svc.startSession(aiPid: 2, toolType: .claudeCode, projectDir: nil, startTime: base.addingTimeInterval(10))
        // At the cap. Starting a third session must evict pid=1 (oldest).
        await svc.startSession(aiPid: 3, toolType: .continuedev, projectDir: nil, startTime: base.addingTimeInterval(20))
        #expect(await svc.snapshot(aiPid: 1) == nil, "Oldest session should have been evicted")
        #expect(await svc.snapshot(aiPid: 2) != nil)
        #expect(await svc.snapshot(aiPid: 3) != nil)
    }
}

@Suite("AgentLineageService: snapshot writer lifecycle")
struct AgentLineageSnapshotWriterTests {

    @Test("slow snapshot persistence does not block live lineage recording")
    func slowPersistenceDoesNotBlockActor() async {
        let probe = LineageSnapshotPersistenceProbe()
        let service = AgentLineageService(
            snapshotPersistence: probe.persist(snapshot:path:)
        )
        await service.startSession(aiPid: 91, toolType: .codex, projectDir: "/project")

        let writer = Task {
            await service.writeSnapshot(to: "/unused/lineage.json")
        }
        let writerEntered = await probe.waitUntilFirstEntered()
        #expect(writerEntered)

        let recordFinished = DispatchSemaphore(value: 0)
        let recorder = Task {
            await service.record(aiPid: 91, kind: .fileRead(path: "/project/a.swift"))
            recordFinished.signal()
        }
        let actorStayedAvailable = await Task.detached {
            // A full parallel run can delay both the recorder and this waiter;
            // use a coarse hang detector while preserving the semantic proof
            // that blocked persistence does not occupy the lineage actor.
            recordFinished.wait(timeout: .now() + 30) == .success
        }.value

        probe.releaseFirstWrite()
        await writer.value
        await recorder.value

        #expect(actorStayedAvailable, "disk publication must not occupy the lineage actor")
        #expect(await service.snapshot(aiPid: 91)?.eventCount == 1)
        let telemetry = await service.snapshotWriteTelemetry()
        #expect(telemetry.offered == 1)
        #expect(telemetry.completed == 1)
        #expect(telemetry.inFlight == 0)
        #expect(telemetry.pending == 0)
        #expect(telemetry.conserved)
    }

    @Test("concurrent snapshots retain only the latest pending generation")
    func latestPendingGenerationWins() async {
        let probe = LineageSnapshotPersistenceProbe()
        let service = AgentLineageService(
            snapshotPersistence: probe.persist(snapshot:path:)
        )
        await service.startSession(aiPid: 92, toolType: .claudeCode, projectDir: "/project")
        await service.record(aiPid: 92, kind: .fileRead(path: "/project/one"))

        let first = Task {
            await service.writeSnapshot(to: "/unused/lineage.json")
        }
        #expect(await probe.waitUntilFirstEntered())

        await service.record(aiPid: 92, kind: .fileRead(path: "/project/two"))
        await service.writeSnapshot(to: "/unused/lineage.json")
        await service.record(aiPid: 92, kind: .fileRead(path: "/project/three"))
        await service.writeSnapshot(to: "/unused/lineage.json")

        let blocked = await service.snapshotWriteTelemetry()
        #expect(blocked.offered == 3)
        #expect(blocked.started == 1)
        #expect(blocked.superseded == 1)
        #expect(blocked.inFlight == 1)
        #expect(blocked.pending == 1)
        #expect(blocked.conserved)

        probe.releaseFirstWrite()
        await first.value

        #expect(probe.eventCounts() == [1, 3], "the superseded two-event snapshot must never be encoded or written")
        let drained = await service.snapshotWriteTelemetry()
        #expect(drained.offered == 3)
        #expect(drained.started == 2)
        #expect(drained.completed == 2)
        #expect(drained.failed == 0)
        #expect(drained.superseded == 1)
        #expect(drained.inFlight == 0)
        #expect(drained.pending == 0)
        #expect(drained.conserved)
    }

    @Test("snapshot persistence failures are terminal and conserved")
    func failuresAreAccounted() async {
        let service = AgentLineageService(
            snapshotPersistence: { _, _ in "injected write failure" }
        )
        await service.writeSnapshot(to: "/unused/lineage.json")

        let telemetry = await service.snapshotWriteTelemetry()
        #expect(telemetry.offered == 1)
        #expect(telemetry.started == 1)
        #expect(telemetry.completed == 0)
        #expect(telemetry.failed == 1)
        #expect(telemetry.inFlight == 0)
        #expect(telemetry.pending == 0)
        #expect(telemetry.conserved)
    }
}
