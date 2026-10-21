import Foundation
import Testing
@testable import MacCrabAgentKit
@testable import MacCrabCore

/// An on-demand size-cap sweep (dashboard flush, SIGHUP, SIGUSR2, boot
/// recovery) waits for journal expiry to yield instead of losing one attempt
/// to it, and never leaves a stale wait behind; a journal-expiry continuation
/// starts from a fresh cutoff.
@Suite("Storage maintenance waits and continuations")
struct StorageMaintenanceWaitTests {
    private func store() throws -> (EventStore, URL) {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrab-maintenance-wait-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        return (try EventStore(directory: directory.path), directory)
    }

    @Test("a sweep refused by journal expiry waits and acquires once expiry yields")
    func sweepWaitsForExpiry() async throws {
        let (store, directory) = try store()
        defer { try? FileManager.default.removeItem(at: directory) }
        #expect(await store.beginJournalExpiryPrune())
        let sweep = Task { await acquireSizeCapSweep(eventStore: store, waitSeconds: 10) }
        // Release only once the sweep has registered its wait.
        let clock = ContinuousClock()
        let deadline = clock.now.advanced(by: .seconds(5))
        while await !store.sizeCapSweepIsWaiting, clock.now < deadline {
            try await Task.sleep(for: .milliseconds(5))
        }
        #expect(await store.sizeCapSweepIsWaiting)
        await store.endSizeCapPrune()
        // Expiry's next quantum yields to the waiting sweep.
        #expect(await store.beginJournalExpiryPrune() == false)
        #expect(await sweep.value)
        await store.endSizeCapPrune()
    }

    @Test("a sweep that times out or is cancelled withdraws its wait, so expiry runs again")
    func failedWaitIsWithdrawn() async throws {
        let (store, directory) = try store()
        defer { try? FileManager.default.removeItem(at: directory) }
        #expect(await store.beginJournalExpiryPrune())
        #expect(await acquireSizeCapSweep(eventStore: store, waitSeconds: 0.4) == false)
        await store.endSizeCapPrune()
        #expect(await store.beginJournalExpiryPrune())

        let sweep = Task { await acquireSizeCapSweep(eventStore: store, waitSeconds: 30) }
        try await Task.sleep(for: .milliseconds(300))
        sweep.cancel()
        #expect(await sweep.value == false)
        await store.endSizeCapPrune()
        #expect(await store.beginJournalExpiryPrune())
        await store.endSizeCapPrune()
    }

    @Test("on-demand enforcement waits through the shared acquisition, and a continuation takes a fresh cutoff")
    func wiring() throws {
        let start = Date(timeIntervalSince1970: 1_700_000_000)
        #expect(JournalExpiryBackpressurePolicy.continuation(at: start)
            == .init(retainedThrough: start, consecutiveWaitSeconds: 0, cumulativeWaitSeconds: 0))
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let timers = try String(contentsOf: root.appendingPathComponent("Sources/MacCrabAgentKit/DaemonTimers.swift"),
                                encoding: .utf8)
        let enforce = try #require(timers.range(of: "private func enforceDatabaseSizeCap("))
        #expect(timers[enforce.lowerBound...].prefix(1_500)
            .contains("guard await acquireSizeCapSweep(eventStore: eventStore, waitSeconds: 60) else {"))
        let continuation = try #require(timers.range(of: "case .continueAfterDelay:"))
        let branch = timers[continuation.lowerBound...].prefix(1_400)
        #expect(branch.contains("let fresh = JournalExpiryBackpressurePolicy.continuation(at: Date())"))
        #expect(branch.contains("retainedThrough = fresh.retainedThrough"))
        #expect(branch.contains("cumulativeWaitSeconds = fresh.cumulativeWaitSeconds"))
    }
}
