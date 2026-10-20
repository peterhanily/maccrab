import Foundation
import Testing
@testable import MacCrabCore

/// The heartbeat reads blocker stats every 30 s. With prevention off nothing
/// else refreshed the PF probe, so every heartbeat forked pfctl.
@Suite("Network blocker stats reuse a recent PF probe")
struct NetworkBlockerStatsProbeTests {
    private final class Clock: @unchecked Sendable {
        private let lock = NSLock()
        private var current: TimeInterval = 1_000
        private var probes = 0
        func advance(_ seconds: TimeInterval) { lock.lock(); current += seconds; lock.unlock() }
        var now: TimeInterval { lock.lock(); defer { lock.unlock() }; return current }
        func probed() { lock.lock(); probes += 1; lock.unlock() }
        var probeCount: Int { lock.lock(); defer { lock.unlock() }; return probes }
    }

    @Test("stats probe once per lifetime; enforcement() stays live")
    func statsReuseProbe() async {
        let clock = Clock()
        let blocker = NetworkBlocker(probe: { _ in
            clock.probed()
            return PFEnforcement.Status(pfEnabled: false, anchorReachable: false, reason: "pf disabled")
        }, now: { clock.now })
        for _ in 0..<10 {
            _ = await blocker.stats()
            clock.advance(30)
        }
        #expect(clock.probeCount == 1)
        clock.advance(NetworkBlocker.statsProbeLifetime)
        let stats = await blocker.stats()
        #expect(clock.probeCount == 2)
        #expect(!stats.enforcing && stats.reason == "pf disabled")
        _ = await blocker.enforcement()
        _ = await blocker.enforcement()
        #expect(clock.probeCount == 4)
    }
}
