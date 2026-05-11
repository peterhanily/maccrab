// CompactPersistentLineageTests.swift
// v1.10 TraceGraph (PR-6a) — tests for CompactPersistentLineage
// protocol and the InMemoryCompactPersistentLineage implementation.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("TraceGraph: CompactPersistentLineage (in-memory)")
struct CompactPersistentLineageTests {

    private func makeSkeleton(
        key: String,
        parentKey: String? = nil,
        pid: pid_t = 1234,
        executable: String = "/usr/bin/example"
    ) -> ProcessSkeleton {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        return ProcessSkeleton(
            processKey: key,
            pid: pid,
            ppid: 1,
            startTime: now,
            executablePath: executable,
            parentProcessKey: parentKey,
            signingSummary: nil,
            firstSeen: now,
            lastSeen: now
        )
    }

    @Test("Promote then look up returns the same skeleton")
    func promoteAndLookup() async throws {
        let lineage = InMemoryCompactPersistentLineage()
        let skeleton = makeSkeleton(key: "abc")
        try await lineage.promote(skeleton)
        let found = try await lineage.skeleton(forProcessKey: "abc")
        #expect(found == skeleton)
    }

    @Test("Promote is idempotent — second call overwrites")
    func promoteIdempotent() async throws {
        let lineage = InMemoryCompactPersistentLineage()
        let s1 = makeSkeleton(key: "abc", executable: "/bin/sh")
        let s2 = makeSkeleton(key: "abc", executable: "/bin/zsh")
        try await lineage.promote(s1)
        try await lineage.promote(s2)
        let found = try await lineage.skeleton(forProcessKey: "abc")
        #expect(found?.executablePath == "/bin/zsh")
        #expect(try await lineage.count() == 1)
    }

    @Test("ancestors() walks the parent chain in closest-first order")
    func ancestorChain() async throws {
        let lineage = InMemoryCompactPersistentLineage()
        // grandparent → parent → child
        try await lineage.promote(makeSkeleton(key: "grandparent"))
        try await lineage.promote(makeSkeleton(key: "parent", parentKey: "grandparent"))
        try await lineage.promote(makeSkeleton(key: "child", parentKey: "parent"))

        let ancestors = try await lineage.ancestors(of: "child", depth: 5)
        #expect(ancestors.count == 2)
        #expect(ancestors[0].processKey == "parent")
        #expect(ancestors[1].processKey == "grandparent")
    }

    @Test("ancestors() respects the depth cap")
    func ancestorsRespectDepth() async throws {
        let lineage = InMemoryCompactPersistentLineage()
        try await lineage.promote(makeSkeleton(key: "g"))
        try await lineage.promote(makeSkeleton(key: "p", parentKey: "g"))
        try await lineage.promote(makeSkeleton(key: "c", parentKey: "p"))

        let oneHop = try await lineage.ancestors(of: "c", depth: 1)
        #expect(oneHop.count == 1)
        #expect(oneHop[0].processKey == "p")
    }

    @Test("ancestors() returns empty for unknown skeleton")
    func unknownSkeleton() async throws {
        let lineage = InMemoryCompactPersistentLineage()
        let result = try await lineage.ancestors(of: "nonexistent", depth: 5)
        #expect(result.isEmpty)
    }

    @Test("ancestors() guards against cycles")
    func cycleGuard() async throws {
        let lineage = InMemoryCompactPersistentLineage()
        // Construct an unnatural cycle: a → b → a. Should not be
        // possible in real data but the guard exists in case storage
        // is ever corrupted.
        try await lineage.promote(makeSkeleton(key: "a", parentKey: "b"))
        try await lineage.promote(makeSkeleton(key: "b", parentKey: "a"))

        let ancestorsOfA = try await lineage.ancestors(of: "a", depth: 10)
        // At most one full loop: b is reported, then the cycle guard halts.
        #expect(ancestorsOfA.count <= 2)
    }

    @Test("ancestors() with depth 0 returns empty")
    func zeroDepth() async throws {
        let lineage = InMemoryCompactPersistentLineage()
        try await lineage.promote(makeSkeleton(key: "p"))
        try await lineage.promote(makeSkeleton(key: "c", parentKey: "p"))

        let result = try await lineage.ancestors(of: "c", depth: 0)
        #expect(result.isEmpty)
    }

    @Test("Reparenting updates the children index")
    func reparentingUpdatesChildren() async throws {
        let lineage = InMemoryCompactPersistentLineage()
        try await lineage.promote(makeSkeleton(key: "oldParent"))
        try await lineage.promote(makeSkeleton(key: "newParent"))
        try await lineage.promote(makeSkeleton(key: "child", parentKey: "oldParent"))

        // Re-promote with a different parent.
        try await lineage.promote(makeSkeleton(key: "child", parentKey: "newParent"))

        let oldChildren = await lineage.children(of: "oldParent")
        let newChildren = await lineage.children(of: "newParent")
        #expect(!oldChildren.contains("child"))
        #expect(newChildren.contains("child"))
    }

    @Test("count reflects the number of unique promoted skeletons")
    func countReflectsState() async throws {
        let lineage = InMemoryCompactPersistentLineage()
        #expect(try await lineage.count() == 0)
        try await lineage.promote(makeSkeleton(key: "a"))
        try await lineage.promote(makeSkeleton(key: "b"))
        try await lineage.promote(makeSkeleton(key: "c"))
        #expect(try await lineage.count() == 3)
    }
}
