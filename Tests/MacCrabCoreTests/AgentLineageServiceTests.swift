// AgentLineageServiceTests.swift
//
// Coverage for the v1.6.6 Agent Data Lineage service: session
// lifecycle, ring-buffer eviction, chronological ordering, and
// cross-event-kind timeline assembly.

import Testing
import Foundation
@testable import MacCrabCore

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
