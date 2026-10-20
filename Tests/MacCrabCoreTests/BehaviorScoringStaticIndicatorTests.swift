import Foundation
import Testing
@testable import MacCrabCore

/// A property of the process (unsigned, runs from /tmp) is not new behaviour
/// each time the process does something; only actions repeat.
@Suite("Behavior scoring counts process-static indicators once")
struct BehaviorScoringStaticIndicatorTests {
    private final class Clock: @unchecked Sendable {
        private let lock = NSLock()
        private var current = Date(timeIntervalSince1970: 1_700_000_000)
        var now: Date { lock.lock(); defer { lock.unlock() }; return current }
        func advance(_ seconds: TimeInterval) { lock.lock(); current += seconds; lock.unlock() }
    }

    @Test("a static indicator reported on every event never walks the score past one weight")
    func staticIndicatorCountsOnce() async {
        let clock = Clock()
        let scorer = BehaviorScoring(alertThreshold: 10, criticalThreshold: 20, decayHalfLife: 300,
                                     maxTrackedProcesses: 100, now: { clock.now })
        var crossed = false
        for _ in 0..<40 {
            if await scorer.addIndicator(.init(name: "executed_from_tmp", weight: 4),
                                         forProcess: 7, path: "/tmp/agent") != nil { crossed = true }
            if await scorer.addIndicator(.init(name: "unsigned_binary", weight: 3),
                                         forProcess: 7, path: "/tmp/agent") != nil { crossed = true }
            clock.advance(121)
        }
        #expect(!crossed, "no new behaviour must not reach the alert threshold")
        #expect(await scorer.score(forPid: 7, path: "/tmp/agent") <= 7)

        // An action indicator still accrues each cooldown period.
        for _ in 0..<6 {
            _ = await scorer.addIndicator(.init(name: "writes_launch_agent", weight: 3),
                                          forProcess: 8, path: "/tmp/agent2")
            clock.advance(121)
        }
        #expect(await scorer.score(forPid: 8, path: "/tmp/agent2") > 3)
    }
}
