// ProcessLineageTraceGraphTests.swift
// v1.10 TraceGraph (PR-6a tail) — tests for the additive
// ProcessLineage extensions: setProcessKey, skeleton(forPid:),
// promotion buffer on eviction, drainPendingPromotions.
//
// These tests must coexist with the existing v1.9 ProcessLineage
// tests (which remain unchanged); together they verify the v1.10
// surface is purely additive — v1.9 nodes (no processKey) behave
// exactly as before.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("TraceGraph: ProcessLineage v1.10 extensions")
struct ProcessLineageTraceGraphTests {

    private func makeLineage() -> ProcessLineage {
        ProcessLineage(retentionWindow: 60, maxAncestorDepth: 8, maxProcessCount: 1000)
    }

    @Test("skeleton(forPid:) returns nil before setProcessKey is called")
    func skeletonNilWithoutKey() async {
        let lineage = makeLineage()
        await lineage.recordProcess(
            pid: 100, ppid: 1,
            path: "/usr/bin/example", name: "example",
            startTime: Date()
        )
        let skeleton = await lineage.skeleton(forPid: 100)
        #expect(skeleton == nil)
    }

    @Test("setProcessKey populates the v1.10 fields and skeleton(forPid:) returns them")
    func setKeyPopulates() async {
        let lineage = makeLineage()
        await lineage.recordProcess(
            pid: 100, ppid: 1,
            path: "/usr/bin/example", name: "example",
            startTime: Date(timeIntervalSince1970: 1_700_000_000)
        )
        await lineage.setProcessKey(
            pid: 100,
            processKey: "abc123",
            parentProcessKey: "parent-key",
            signingSummary: ProcessSkeleton.SigningSummary(
                signerType: .apple,
                isAppleSigned: true,
                isNotarized: true
            )
        )
        let skeleton = await lineage.skeleton(forPid: 100)
        #expect(skeleton?.processKey == "abc123")
        #expect(skeleton?.parentProcessKey == "parent-key")
        #expect(skeleton?.signingSummary?.signerType == .apple)
        #expect(skeleton?.signingSummary?.isAppleSigned == true)
        #expect(skeleton?.executablePath == "/usr/bin/example")
        #expect(skeleton?.pid == 100)
        #expect(skeleton?.ppid == 1)
    }

    @Test("setProcessKey on an unknown pid is a no-op")
    func setKeyOnUnknown() async {
        let lineage = makeLineage()
        await lineage.setProcessKey(pid: 999, processKey: "x")
        let skeleton = await lineage.skeleton(forPid: 999)
        #expect(skeleton == nil)
    }

    @Test("Eviction via prune enqueues a skeleton when processKey is set")
    func pruneEvictionPromotes() async {
        let lineage = ProcessLineage(retentionWindow: 0.1, maxAncestorDepth: 8, maxProcessCount: 1000)
        let now = Date()
        await lineage.recordProcess(
            pid: 200, ppid: 1,
            path: "/usr/bin/sample", name: "sample",
            startTime: now
        )
        await lineage.setProcessKey(pid: 200, processKey: "key-200", parentProcessKey: "key-1")
        await lineage.recordExit(pid: 200)

        // Wait for the retention window to expire, then prune.
        try? await Task.sleep(nanoseconds: 200_000_000)
        await lineage.prune()

        let drained = await lineage.drainPendingPromotions()
        #expect(drained.count == 1)
        #expect(drained.first?.processKey == "key-200")
        #expect(drained.first?.parentProcessKey == "key-1")
    }

    @Test("Eviction does NOT enqueue a skeleton for v1.9-only nodes (no processKey)")
    func v19NodesNotPromoted() async {
        let lineage = ProcessLineage(retentionWindow: 0.1, maxAncestorDepth: 8, maxProcessCount: 1000)
        await lineage.recordProcess(
            pid: 300, ppid: 1,
            path: "/usr/bin/legacy", name: "legacy",
            startTime: Date()
        )
        // No setProcessKey call — this represents a v1.9-only collector path.
        await lineage.recordExit(pid: 300)
        try? await Task.sleep(nanoseconds: 200_000_000)
        await lineage.prune()

        let drained = await lineage.drainPendingPromotions()
        #expect(drained.isEmpty)
    }

    @Test("LRU eviction under cap pressure also enqueues skeletons")
    func lruPressurePromotes() async {
        // Cap of 2 to force eviction immediately.
        let lineage = ProcessLineage(retentionWindow: 3600, maxAncestorDepth: 8, maxProcessCount: 2)
        await lineage.recordProcess(pid: 1, ppid: 0, path: "/a", name: "a", startTime: Date())
        await lineage.setProcessKey(pid: 1, processKey: "k-1")
        await lineage.recordExit(pid: 1)   // marks pid 1 as the eviction-preferred node

        await lineage.recordProcess(pid: 2, ppid: 0, path: "/b", name: "b", startTime: Date())
        await lineage.setProcessKey(pid: 2, processKey: "k-2")
        // Adding pid 3 takes us to 3 nodes; one must be evicted (pid 1 since it has exitTime set).
        await lineage.recordProcess(pid: 3, ppid: 0, path: "/c", name: "c", startTime: Date())

        let drained = await lineage.drainPendingPromotions()
        #expect(drained.count == 1)
        #expect(drained.first?.processKey == "k-1")
    }

    @Test("drainPendingPromotions returns then clears the buffer")
    func drainClearsBuffer() async {
        let lineage = ProcessLineage(retentionWindow: 0.1, maxAncestorDepth: 8, maxProcessCount: 1000)
        for n in 1...5 {
            let pid = pid_t(400 + n)
            await lineage.recordProcess(pid: pid, ppid: 1, path: "/x", name: "x", startTime: Date())
            await lineage.setProcessKey(pid: pid, processKey: "k-\(n)")
            await lineage.recordExit(pid: pid)
        }
        try? await Task.sleep(nanoseconds: 200_000_000)
        await lineage.prune()

        let first = await lineage.drainPendingPromotions()
        #expect(first.count == 5)

        let second = await lineage.drainPendingPromotions()
        #expect(second.isEmpty)
    }

    @Test("Skeleton's lastSeen reflects exitTime when present")
    func skeletonLastSeenFromExit() async {
        let lineage = makeLineage()
        let start = Date(timeIntervalSince1970: 1_700_000_000)
        await lineage.recordProcess(pid: 500, ppid: 1, path: "/x", name: "x", startTime: start)
        await lineage.setProcessKey(pid: 500, processKey: "k")
        let skeleton1 = await lineage.skeleton(forPid: 500)
        // Before exit, lastSeen == startTime
        #expect(skeleton1?.lastSeen == start)

        await lineage.recordExit(pid: 500)
        let skeleton2 = await lineage.skeleton(forPid: 500)
        // After exit, lastSeen has advanced (exitTime was set to ~now)
        #expect(skeleton2 != nil)
        #expect((skeleton2?.lastSeen.timeIntervalSince1970 ?? 0) > start.timeIntervalSince1970)
    }
}
