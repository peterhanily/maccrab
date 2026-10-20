import Foundation
import Testing
@testable import MacCrabCore

/// Overlapping TCC database notifications must not diff concurrently
/// against one snapshot: each permission transition is emitted once.
@Suite("TCC monitor change passes")
struct TCCMonitorChangePassTests {
    /// Entries returned by the injected reader; reads block while closed.
    private final class Source: @unchecked Sendable {
        private let condition = NSCondition()
        private var entries: [String: TCCEntry] = [:]
        private var open = true
        private(set) var blockedReads = 0

        func set(_ value: [String: TCCEntry]) {
            condition.lock(); entries = value; condition.unlock()
        }
        func close() { condition.lock(); open = false; condition.unlock() }
        func reopen() { condition.lock(); open = true; condition.broadcast(); condition.unlock() }
        var waiting: Int { condition.lock(); defer { condition.unlock() }; return blockedReads }
        func read() -> [String: TCCEntry] {
            condition.lock(); defer { condition.unlock() }
            blockedReads += 1
            while !open { condition.wait() }
            blockedReads -= 1
            return entries
        }
    }

    private func grant(_ client: String) -> TCCEntry {
        TCCEntry(service: "kTCCServiceAccessibility", client: client, clientType: 0,
                 authValue: 2, authReason: 2, indirectObjectIdentifier: "UNUSED",
                 flags: 0, lastModified: 0, source: "user")
    }

    private func actions(from monitor: TCCMonitor, within duration: Duration) async -> [String] {
        let collector = Task { () -> [String] in
            var seen: [String] = []
            for await event in monitor.events { seen.append(event.eventAction) }
            return seen
        }
        try? await Task.sleep(for: duration)
        collector.cancel()
        return await collector.value
    }

    @Test("a notification during a pass reruns it instead of emitting the transition twice")
    func overlappingNotificationsEmitOnce() async throws {
        let source = Source()
        let monitor = TCCMonitor(entriesReaderForTesting: { source.read() }, debounceInterval: 0)
        await monitor.start()

        let entry = grant("com.example.app")
        source.set([entry.identityKey: entry])
        source.close()
        let first = Task { await monitor.databaseChangedForTesting() }
        let clock = ContinuousClock()
        let deadline = clock.now.advanced(by: .seconds(10))
        while source.waiting < 1, clock.now < deadline {
            try await Task.sleep(for: .milliseconds(5))
        }
        #expect(source.waiting == 1, "the first pass must be inside its read")
        let second = Task { await monitor.databaseChangedForTesting() }
        try await Task.sleep(for: .milliseconds(100))
        source.reopen()
        await first.value
        await second.value

        // A later change is seen, not swallowed by the debounce.
        source.set([:])
        await monitor.databaseChangedForTesting()

        let emitted = await actions(from: monitor, within: .milliseconds(300))
        #expect(emitted.filter { $0 == "tcc_grant" }.count == 1)
        #expect(emitted.filter { $0 == "tcc_revoke" }.count == 1)
        _ = await monitor.stopAndJoin()
    }
}
