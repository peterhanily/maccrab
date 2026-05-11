// EdgeBuilderTraceGraphTests.swift
// v1.10 TraceGraph (PR-7) — tests for EdgeBuilder.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("TraceGraph: EdgeBuilder")
struct EdgeBuilderTraceGraphTests {

    private let now = Date(timeIntervalSince1970: 1_700_000_000)

    @Test("Edge id is deterministic — same triple → same id")
    func edgeIdDeterministic() {
        let id1 = EdgeBuilder.edgeId(
            sourceEntityId: "process:a",
            targetEntityId: "process:b",
            relation: .spawned
        )
        let id2 = EdgeBuilder.edgeId(
            sourceEntityId: "process:a",
            targetEntityId: "process:b",
            relation: .spawned
        )
        #expect(id1 == id2)
        #expect(id1.count == 64)
    }

    @Test("Different triples produce different ids")
    func edgeIdUnique() {
        let id1 = EdgeBuilder.edgeId(sourceEntityId: "process:a", targetEntityId: "process:b", relation: .spawned)
        let id2 = EdgeBuilder.edgeId(sourceEntityId: "process:b", targetEntityId: "process:a", relation: .spawned)
        let id3 = EdgeBuilder.edgeId(sourceEntityId: "process:a", targetEntityId: "process:b", relation: .read)
        #expect(id1 != id2)
        #expect(id1 != id3)
        #expect(id2 != id3)
    }

    @Test("Build between typed nodes wires confidence tier")
    func buildWithTier() {
        let parent = ProcessNode(
            processKey: "p", pid: 1, ppid: 0,
            executablePath: "/bin/sh",
            isAppleSigned: true, isNotarized: true,
            startTime: now
        )
        let child = ProcessNode(
            processKey: "c", pid: 2, ppid: 1,
            executablePath: "/usr/bin/curl",
            isAppleSigned: true, isNotarized: true,
            startTime: now
        )
        let edge = EdgeBuilder.build(
            from: parent,
            to: child,
            relation: .spawned,
            confidence: 0.95,
            observedAt: now,
            eventIds: ["ev-1"]
        )
        #expect(edge.relation == "spawned")
        #expect(edge.confidence == 0.95)
        #expect(edge.confidenceTier == "direct")
        #expect(edge.sourceEntityId == "process:p")
        #expect(edge.targetEntityId == "process:c")
        #expect(edge.eventIdsJson == "[\"ev-1\"]")
    }

    @Test("Multiple event ids serialize as a sorted JSON array")
    func eventIdsSorted() {
        let edge = EdgeBuilder.build(
            sourceEntityId: "a",
            targetEntityId: "b",
            relation: .read,
            confidence: 0.7,
            observedAt: now,
            eventIds: ["z-event", "a-event", "m-event"]
        )
        // Sorted lexically for canonical JSON.
        #expect(edge.eventIdsJson == "[\"a-event\",\"m-event\",\"z-event\"]")
    }

    @Test("Confidence at threshold boundary maps correctly")
    func boundaryTier() {
        let e1 = EdgeBuilder.build(sourceEntityId: "a", targetEntityId: "b",
            relation: .spawned, confidence: 0.90, observedAt: now)
        #expect(e1.confidenceTier == "direct")

        let e2 = EdgeBuilder.build(sourceEntityId: "a", targetEntityId: "b",
            relation: .spawned, confidence: 0.70, observedAt: now)
        #expect(e2.confidenceTier == "strong_inferred")

        let e3 = EdgeBuilder.build(sourceEntityId: "a", targetEntityId: "b",
            relation: .spawned, confidence: 0.30, observedAt: now)
        #expect(e3.confidenceTier == "weak_inferred")

        let e4 = EdgeBuilder.build(sourceEntityId: "a", targetEntityId: "b",
            relation: .spawned, confidence: 0.10, observedAt: now)
        #expect(e4.confidenceTier == "temporal_only")
    }

    @Test("Empty event ids produces empty JSON array")
    func emptyEventIds() {
        let edge = EdgeBuilder.build(sourceEntityId: "a", targetEntityId: "b",
            relation: .read, confidence: 0.5, observedAt: now)
        #expect(edge.eventIdsJson == "[]")
    }
}
