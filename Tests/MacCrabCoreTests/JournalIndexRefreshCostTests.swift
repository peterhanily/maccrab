// JournalIndexRefreshCostTests.swift
//
// v1.21.6-rc.45: the journal-index refresh must report what it costs.
//
// Measured on an installed host: with the dashboard window open, its 5s poll
// cost MORE than five seconds of CPU, so the app never left the read path. All
// 33 microstackshots in the OS-generated cpu_resource.diag rooted at
// `EventStore.exactEventsSnapshot`; one `fs_usage` sample caught 52,188 preads
// in 3 seconds, touching 9,663 distinct pages at a 5.4x re-read factor — to
// serve a request for the newest 200 rows. With the window closed: 0.0% CPU,
// 0 preads.
//
// The cause is that the cheap append-only refresh requires
// `minimumBlockID == journalIndexedMinimumBlockID`, so ANY journal expiry forces
// a full rebuild, and expiry is continuous under a 15-minute retention floor.
// Fixing THAT needs prefix eviction across the packed locator structures and is
// deliberately deferred rather than rushed into the evidence index.
//
// What is fixed here is that the cost was invisible: no counter, no log,
// nothing. These tests pin the reporting, not the performance.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("Journal index refresh cost reporting (v1.21.6-rc.45)")
struct JournalIndexRefreshCostTests {

    @Test("refreshes are counted, and the last duration is retained")
    func refreshesAreCounted() async throws {
        let dir = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("maccrab-idxcost-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }

        let store = try EventStore(directory: dir.path)
        let now = Date()
        for i in 0..<200 {
            let ts = now.addingTimeInterval(-Double(i))
            let proc = ProcessInfo(
                pid: Int32(3000 + i), ppid: 1, rpid: 1,
                name: "idxcost\(i)", executable: "/bin/idxcost\(i)",
                commandLine: "/bin/idxcost\(i)", args: [],
                workingDirectory: "/", userId: 501, userName: "t", groupId: 20,
                startTime: ts, ancestors: [], isPlatformBinary: false
            )
            try await store.insert(event: Event(
                timestamp: ts, eventCategory: .process, eventType: .start,
                eventAction: "exec", process: proc
            ))
        }

        // Any read goes through ensureJournalIndex.
        _ = try await store.exactEventsSnapshot(since: .distantPast, limit: 10)
        let first = await store.journalIndexRefreshDiagnostics()
        #expect(first.refreshes > 0, "a read must record an index refresh")
        let allocated = await store.journalLocatorAllocatedBytes()
        #expect(first.locatorAllocatedBytes == allocated)
        #expect(first.locatorAllocatedBytes > 0)

        _ = try await store.exactEventsSnapshot(since: .distantPast, limit: 10)
        let second = await store.journalIndexRefreshDiagnostics()
        #expect(
            second.refreshes > first.refreshes,
            "every read records its refresh cost, including the cheap early-return path"
        )
        #expect(second.lastNanoseconds > 0, "the measured duration must be retained")
        #expect(second.locatorAllocatedBytes == first.locatorAllocatedBytes,
                "a warm read must report the same retained locator capacity")
    }

    @Test("the slow threshold is a named constant, not a magic number")
    func slowThresholdIsNamed() {
        #expect(EventStore.journalIndexSlowRefreshNanoseconds == 250_000_000)
    }

    @Test("ownership sampling does not build or refresh the journal index")
    func ownershipSamplingIsReadOnly() async throws {
        let dir = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("maccrab-idxownership-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }

        let store = try EventStore(directory: dir.path)
        let before = await store.journalIndexRefreshDiagnostics()
        let allocated = await store.journalLocatorAllocatedBytes()
        let after = await store.journalIndexRefreshDiagnostics()
        #expect(before.locatorAllocatedBytes == allocated)
        #expect(after.locatorAllocatedBytes == allocated)
        #expect(allocated >= 0)
        #expect(after.refreshes == before.refreshes)
        #expect(after.fullRebuilds == before.fullRebuilds)
        #expect(after.appendRefreshes == before.appendRefreshes)
        #expect(after.lastNanoseconds == before.lastNanoseconds)
        #expect(after.stagesNanoseconds == before.stagesNanoseconds)
        #expect(after.stagesComplete == before.stagesComplete)
    }

    @Test("a small store does not trip the slow-refresh counter")
    func smallStoreIsNotSlow() async throws {
        let dir = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("maccrab-idxfast-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }

        let store = try EventStore(directory: dir.path)
        _ = try await store.exactEventsSnapshot(since: .distantPast, limit: 10)
        let d = await store.journalIndexRefreshDiagnostics()
        #expect(
            d.slowRefreshes == 0,
            "an empty store refreshed in \(d.lastNanoseconds / 1_000_000) ms — the threshold would be meaningless if this tripped"
        )
    }
}
