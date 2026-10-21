import Foundation
import Testing
@testable import MacCrabCore

/// Static weight never decays, so it must not decide which scores the table
/// keeps, and a process's scores must not outlive it.
@Suite("Behavior scoring eviction, re-arm and exit")
struct BehaviorScoringStaticFloodTests {
    private final class Clock: @unchecked Sendable {
        private let lock = NSLock()
        private var current = Date(timeIntervalSince1970: 1_700_000_000)
        var now: Date { lock.lock(); defer { lock.unlock() }; return current }
        func advance(_ seconds: TimeInterval) { lock.lock(); current += seconds; lock.unlock() }
    }

    private func scorer(_ clock: Clock, capacity: Int = 50) -> BehaviorScoring {
        BehaviorScoring(alertThreshold: 10, criticalThreshold: 20, decayHalfLife: 300,
                        maxTrackedProcesses: capacity, now: { clock.now })
    }

    /// One burst of /tmp executions: every entry holds only static weight.
    private func floodStaticEntries(_ scorer: BehaviorScoring, count: Int, firstPid: Int32) async {
        for offset in 0..<count {
            _ = await scorer.addIndicator(.init(name: "executed_from_tmp", weight: 4),
                                          forProcess: firstPid + Int32(offset), path: "/tmp/t")
        }
    }

    @Test("a static-only flood does not evict a newcomer whose actions each weigh less")
    func floodDoesNotPinTheTable() async {
        let clock = Clock()
        let scorer = scorer(clock)
        await floodStaticEntries(scorer, count: 50, firstPid: 1)
        var crossing: BehaviorScoring.ScoringResult?
        for name in ["obfuscated_commandline", "shell_spawned_by_non_terminal",
                     "connects_raw_ip_a", "connects_raw_ip_b"] {
            clock.advance(5)
            if let result = await scorer.addIndicator(.init(name: name, weight: 3),
                                                      forProcess: 900, path: "/Users/u/payload") {
                crossing = result
            }
        }
        #expect(crossing != nil, "the payload must accumulate past the threshold")
        #expect(await scorer.lifecycleInvariantFailures().isEmpty)
    }

    @Test("a tracked action score survives a later burst of static-only entries")
    func actionEntrySurvivesStaticBurst() async {
        let clock = Clock()
        let scorer = scorer(clock)
        _ = await scorer.addIndicator(.init(name: "writes_launch_agent", weight: 5),
                                      forProcess: 900, path: "/Users/u/payload")
        // Decayed to about 3.8, below a static entry's 4.
        clock.advance(120)
        await floodStaticEntries(scorer, count: 60, firstPid: 1)
        #expect(await scorer.score(forPid: 900, path: "/Users/u/payload") > 3)
        #expect(await scorer.lifecycleInvariantFailures().isEmpty)
    }

    @Test("a static-only crossing re-arms after a quiet period and keeps its pending delivery")
    func staticOnlyCrossingReArms() async {
        let clock = Clock()
        let scorer = scorer(clock)
        let path = "/opt/homebrew/bin/bash"
        _ = await scorer.addIndicator(.init(name: "ai_tool_runs_sudo", weight: 6), forProcess: 70, path: path)
        let first = await scorer.addIndicator(.init(name: "ai_tool_installs_unknown_pkg", weight: 4),
                                              forProcess: 70, path: path)
        let firstToken = try? #require(first?.deliveryToken)
        // Undelivered, an action returns the same crossing, not a new one.
        clock.advance(1)
        let retried = await scorer.addIndicator(.init(name: "action_a", weight: 2), forProcess: 70, path: path)
        #expect(retried?.deliveryToken == firstToken)
        if let firstToken {
            #expect(await scorer.resolveThreshold(deliveryToken: firstToken, as: .committed))
        }
        // Delivered and still acting: latched.
        clock.advance(1)
        #expect(await scorer.addIndicator(.init(name: "action_b", weight: 2), forProcess: 70, path: path) == nil)
        // After a quiet period a new action alerts again, although the static
        // weight alone still exceeds the threshold.
        clock.advance(1_500)
        let again = await scorer.addIndicator(.init(name: "action_a", weight: 2), forProcess: 70, path: path)
        #expect(again != nil)
        #expect(again?.deliveryToken != firstToken)
        #expect(await scorer.lifecycleInvariantFailures().isEmpty)
    }

    @Test("an exited process's scores serve late events, then leave before pid and path are reused")
    func exitedScoresLeaveAfterGrace() async {
        let clock = Clock()
        let scorer = scorer(clock)
        let path = "/bin/zsh"
        _ = await scorer.addIndicator(.init(name: "ai_tool_runs_sudo", weight: 6), forProcess: 71, path: path)
        let crossing = await scorer.addIndicator(.init(name: "ai_tool_installs_unknown_pkg", weight: 4),
                                                 forProcess: 71, path: path)
        if let token = crossing?.deliveryToken {
            _ = await scorer.resolveThreshold(deliveryToken: token, as: .committed)
        }
        await scorer.processExited(pid: 71)
        // An event still in flight on the other lane keeps accumulating.
        clock.advance(10)
        _ = await scorer.addIndicator(.init(name: "writes_launch_agent", weight: 1), forProcess: 71, path: path)
        #expect(await scorer.score(forPid: 71, path: path) >= 10)
        // After the grace another exit (or the periodic prune) drops it.
        clock.advance(121)
        await scorer.processExited(pid: 72)
        #expect(await scorer.score(forPid: 71, path: path) == 0)
        // A new process reusing pid and path starts unscored and unlatched.
        _ = await scorer.addIndicator(.init(name: "ai_tool_runs_sudo", weight: 6), forProcess: 71, path: path)
        #expect(await scorer.addIndicator(.init(name: "ai_tool_installs_unknown_pkg", weight: 4),
                                          forProcess: 71, path: path) != nil)
        #expect(await scorer.lifecycleInvariantFailures().isEmpty)
    }

    @Test("the periodic prune also drops exited scores past the grace")
    func pruneDropsExitedScores() async {
        let clock = Clock()
        let scorer = scorer(clock)
        _ = await scorer.addIndicator(.init(name: "writes_launch_agent", weight: 5), forProcess: 73, path: "/x")
        await scorer.processExited(pid: 73)
        clock.advance(121)
        await scorer.prune()
        #expect(await scorer.score(forPid: 73, path: "/x") == 0)
        #expect(await scorer.lifecycleInvariantFailures().isEmpty)
    }

    @Test("the daemon prunes scores on a timer and reports exits")
    func wiring() throws {
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        func source(_ path: String) throws -> String {
            try String(contentsOf: root.appendingPathComponent(path), encoding: .utf8)
        }
        let timers = try source("Sources/MacCrabAgentKit/DaemonTimers.swift")
        #expect(timers.contains("await state.behaviorScoring.prune()"))
        let eventLoop = try source("Sources/MacCrabAgentKit/EventLoop.swift")
        let exitBranch = try #require(eventLoop.range(of: "if event.eventAction == \"exit\" {"))
        let branch = eventLoop[exitBranch.upperBound...].prefix(400)
        #expect(branch.contains("await state.behaviorScoring.processExited(pid: event.process.pid)"))
    }
}
