import Foundation
import Testing
@testable import MacCrabCore

/// A block transaction that failed before COMMIT has certainly rolled back,
/// so the authoritative in-memory journal index must survive it. Discarding
/// it made every retry re-verify every retained block.
@Suite("Journal index survives a certain rollback")
struct JournalIndexFailureScopeTests {
    private final class Counter: @unchecked Sendable {
        private let lock = NSLock()
        private var value = 0
        func increment() { lock.lock(); value += 1; lock.unlock() }
        var count: Int { lock.lock(); defer { lock.unlock() }; return value }
    }

    private struct Injected: Error {}

    private func event(_ ordinal: Int) -> Event {
        let process = MacCrabCore.ProcessInfo(
            pid: Int32(30_000 + ordinal), ppid: 1, rpid: 1,
            name: "index-fixture", executable: "/usr/bin/index-fixture",
            commandLine: "index-fixture \(ordinal)", args: [],
            workingDirectory: "/", userId: 501, userName: "fixture",
            groupId: 20, startTime: Date(), ancestors: [], isPlatformBinary: false)
        return Event(timestamp: Date(), eventCategory: .process, eventType: .start,
                     eventAction: "exec", process: process)
    }

    @Test("a failure before COMMIT keeps the index; the retried event then commits")
    func preCommitFailureKeepsIndex() async throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("journal-index-scope-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = try EventStore(path: directory.appendingPathComponent("events.db").path,
                                   liveMemoryBudget: .isolatedProductionEquivalentForTesting())
        _ = try await store.recoverJournalBeforeProducers()
        #expect(try await store.insert(events: [event(0)], lane: .priority).persistedCount == 1)
        #expect(try await store.count() == 1)

        let rebuilds = Counter()
        await store.setJournalIndexRebuildHookForTesting { _ in rebuilds.increment() }
        await store.setJournalBlockPreCommitFailureForTesting { throw Injected() }
        let retried = event(1)
        await #expect(throws: (any Error).self) {
            _ = try await store.insert(events: [retried], lane: .priority)
        }
        await store.setJournalBlockPreCommitFailureForTesting(nil)
        #expect(try await store.insert(events: [retried], lane: .priority).persistedCount == 1)
        #expect(try await store.count() == 2)
        #expect(rebuilds.count == 0, "a certain rollback must not force a full index rebuild")
    }
}
