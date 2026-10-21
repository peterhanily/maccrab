import Foundation
import Testing
@testable import MacCrabAgentKit
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
        // Still kept just inside the grace, for a lagging file lane.
        clock.advance(589)
        await scorer.processExited(pid: 72)
        #expect(await scorer.score(forPid: 71, path: path) >= 10)
        // After the grace another exit (or the periodic prune) drops it.
        clock.advance(2)
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
        clock.advance(601)
        await scorer.prune()
        #expect(await scorer.score(forPid: 73, path: "/x") == 0)
        #expect(await scorer.lifecycleInvariantFailures().isEmpty)
    }

    @Test("a newcomer with only static weight is not evicted on insert by a table of action residue")
    func staticNewcomerSurvivesActionResidue() async {
        let clock = Clock()
        let scorer = scorer(clock)
        for offset in 0..<50 {
            _ = await scorer.addIndicator(.init(name: "connects_raw_ip", weight: 1),
                                          forProcess: Int32(1 + offset), path: "/usr/bin/true")
        }
        clock.advance(1)
        let path = "/opt/homebrew/bin/bash"
        _ = await scorer.addIndicator(.init(name: "ai_tool_runs_sudo", weight: 6), forProcess: 900, path: path)
        let crossing = await scorer.addIndicator(.init(name: "ai_tool_installs_unknown_pkg", weight: 4),
                                                 forProcess: 900, path: path)
        #expect(crossing != nil, "the static-only total must form and cross")
        #expect(await scorer.lifecycleInvariantFailures().isEmpty)
    }

    @Test("exited processes are evicted before live ones")
    func exitedScoresEvictFirst() async {
        let clock = Clock()
        let scorer = scorer(clock, capacity: 3)
        _ = await scorer.addIndicator(.init(name: "writes_launch_agent", weight: 8), forProcess: 1, path: "/a")
        _ = await scorer.addIndicator(.init(name: "connects_raw_ip", weight: 2), forProcess: 2, path: "/b")
        _ = await scorer.addIndicator(.init(name: "connects_raw_ip", weight: 2), forProcess: 3, path: "/c")
        await scorer.processExited(pid: 1)
        _ = await scorer.addIndicator(.init(name: "connects_raw_ip", weight: 3), forProcess: 4, path: "/d")
        #expect(await scorer.score(forPid: 1, path: "/a") == 0, "the exited entry goes first")
        #expect(await scorer.score(forPid: 2, path: "/b") > 0)
        #expect(await scorer.score(forPid: 3, path: "/c") > 0)
        #expect(await scorer.lifecycleInvariantFailures().isEmpty)
    }

    @Test("a burst of exits expiring together drains in one pass")
    func exitBurstDrainsInOnePass() async {
        let clock = Clock()
        let count = 8_000
        let scorer = scorer(clock, capacity: count)
        for pid in 1...count {
            _ = await scorer.addIndicator(.init(name: "connects_raw_ip", weight: 1),
                                          forProcess: Int32(pid), path: "/private/tmp/burst/payload")
        }
        for pid in 1...count { await scorer.processExited(pid: Int32(pid)) }
        clock.advance(601)
        let started = DispatchTime.now().uptimeNanoseconds
        await scorer.processExited(pid: Int32(count + 1))
        let seconds = Double(DispatchTime.now().uptimeNanoseconds - started) / 1e9
        #expect(await scorer.score(forPid: 1, path: "/private/tmp/burst/payload") == 0)
        // One pass over the table, not one per expired pid.
        #expect(seconds < 0.75, "drain took \(seconds) s")
        #expect(await scorer.lifecycleInvariantFailures().isEmpty)
    }

    @Test("one event's indicators land together, so an insert between them cannot split the crossing")
    func eventIndicatorsLandTogether() async throws {
        let clock = Clock()
        let scorer = scorer(clock)
        // Every slot holds a small action residue.
        for pid in 1...50 {
            _ = await scorer.addIndicator(.init(name: "connects_raw_ip", weight: 1),
                                          forProcess: Int32(pid), path: "/usr/bin/curl")
        }
        clock.advance(1)
        // Applied one call at a time, an insert landing between sudo and the
        // install evicts the static-only entry and the 10 never forms.
        _ = await scorer.addIndicator(.init(name: "ai_tool_runs_sudo", weight: 6), forProcess: 900, path: "/usr/bin/sudo")
        _ = await scorer.addIndicator(.init(name: "connects_raw_ip", weight: 1), forProcess: 901, path: "/usr/bin/nc")
        let split = await scorer.addIndicator(.init(name: "ai_tool_installs_unknown_pkg", weight: 4),
                                              forProcess: 900, path: "/usr/bin/sudo")
        #expect(split == nil, "the hazard the event-level batch removes")
        // Applied together, they cross.
        let together = await scorer.addIndicators(
            [.init(name: "ai_tool_runs_sudo", weight: 6), .init(name: "ai_tool_installs_unknown_pkg", weight: 4)],
            forProcess: 902, path: "/usr/bin/sudo")
        #expect(together != nil)
        #expect(await scorer.lifecycleInvariantFailures().isEmpty)
        // The event loop reports an AI child's indicators in one call.
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let eventLoop = try String(
            contentsOf: root.appendingPathComponent("Sources/MacCrabAgentKit/EventLoop.swift"), encoding: .utf8)
        let start = try #require(eventLoop.range(of: "private static func enforceAIChildBehaviorGuards("))
        let end = try #require(eventLoop.range(
            of: "// Prompt injection scanning", range: start.upperBound..<eventLoop.endIndex))
        let body = eventLoop[start.upperBound..<end.lowerBound]
        #expect(body.components(separatedBy: "BehaviorScoreAlertEmitter.record(").count == 2)
        #expect(body.contains("indicators: indicators"))
    }

    @Test("an exit storm keeps the exit queue proportional to the table")
    func exitQueueStaysBounded() async {
        let clock = Clock()
        let capacity = 100
        let scorer = scorer(clock, capacity: capacity)
        var longest = 0
        for pid in 1...50_000 {
            _ = await scorer.addIndicator(.init(name: "connects_raw_ip", weight: 1),
                                          forProcess: Int32(pid), path: "/private/tmp/storm/payload")
            await scorer.processExited(pid: Int32(pid))
            longest = max(longest, await scorer.exitQueueLength)
        }
        #expect(longest <= 4 * capacity, "queue reached \(longest)")
        #expect(await scorer.lifecycleInvariantFailures().isEmpty)
        // The surviving exited scores still leave after the grace.
        clock.advance(601)
        await scorer.processExited(pid: 60_000)
        #expect(await scorer.score(forPid: 50_000, path: "/private/tmp/storm/payload") == 0)
    }

    @Test("a later process reusing an exited pid and path starts a new generation")
    func reusedPidStartsANewGeneration() async throws {
        let clock = Clock()
        let scorer = scorer(clock)
        let path = "/opt/homebrew/bin/node"
        let firstStart = clock.now
        let first = await scorer.addIndicators(
            [.init(name: "ai_tool_runs_sudo", weight: 6), .init(name: "ai_tool_installs_unknown_pkg", weight: 4)],
            forProcess: 70, path: path, processStart: firstStart)
        let token = try #require(first?.deliveryToken)
        #expect(await scorer.resolveThreshold(deliveryToken: token, as: .committed))
        clock.advance(1)
        await scorer.processExited(pid: 70)
        // A late event of the exited process keeps its score (and, after the
        // quiet period, alerts again; deliver that too).
        clock.advance(1)
        if let late = await scorer.addIndicator(.init(name: "connects_raw_ip", weight: 2),
                                                forProcess: 70, path: path, processStart: firstStart) {
            #expect(await scorer.resolveThreshold(deliveryToken: late.deliveryToken, as: .committed))
        }
        #expect(await scorer.score(forPid: 70, path: path) >= 11.9)
        // A process with the same pid and path that started after the exit
        // is scored on its own: unlatched, live and without the old weight.
        clock.advance(1)
        let second = await scorer.addIndicators(
            [.init(name: "ai_tool_runs_sudo", weight: 6), .init(name: "ai_tool_installs_unknown_pkg", weight: 4)],
            forProcess: 70, path: path, processStart: clock.now)
        #expect(second != nil)
        #expect(await scorer.score(forPid: 70, path: path) < 10.5)
        // No longer exited: the old exit does not drop it after the grace.
        clock.advance(601)
        await scorer.processExited(pid: 71)
        #expect(await scorer.score(forPid: 70, path: path) >= 10)
        #expect(await scorer.lifecycleInvariantFailures().isEmpty)
    }

    @Test("a new generation leaves the exited process's undelivered crossing pending")
    func pendingCrossingSurvivesNewGeneration() async throws {
        let clock = Clock()
        let scorer = scorer(clock)
        let path = "/bin/sh"
        let crossing = await scorer.addIndicators(
            [.init(name: "ai_tool_runs_sudo", weight: 6), .init(name: "ai_tool_installs_unknown_pkg", weight: 4)],
            forProcess: 80, path: path, processStart: clock.now)
        let token = try #require(crossing?.deliveryToken)
        await scorer.recordThresholdDeliveryFailure(deliveryToken: token)
        clock.advance(1)
        await scorer.processExited(pid: 80)
        clock.advance(1)
        // A process reusing the pid and path starts afresh, but the exited
        // process's crossing is still retried until it settles.
        let retried = await scorer.addIndicator(.init(name: "connects_raw_ip", weight: 2),
                                                forProcess: 80, path: path, processStart: clock.now)
        #expect(retried?.deliveryToken == token)
        var telemetry = await scorer.thresholdTelemetry()
        #expect(telemetry.abandoned == 0 && telemetry.pending == 1)
        #expect(await scorer.score(forPid: 80, path: path) < 2.5)
        #expect(await scorer.resolveThreshold(deliveryToken: token, as: .committed))
        telemetry = await scorer.thresholdTelemetry()
        #expect(telemetry.committed == 1 && telemetry.conservesCrossings)
        #expect(await scorer.lifecycleInvariantFailures().isEmpty)
    }

    @Test("a new generation whose own exit came first starts out exited")
    func exitedGenerationStaysExited() async {
        let clock = Clock()
        let scorer = scorer(clock)
        let path = "/bin/sh"
        _ = await scorer.addIndicator(.init(name: "connects_raw_ip", weight: 2),
                                      forProcess: 90, path: path, processStart: clock.now)
        clock.advance(1)
        await scorer.processExited(pid: 90)
        clock.advance(1)
        let laterStart = clock.now
        clock.advance(1)
        // The later process exits before any of its events is scored.
        await scorer.processExited(pid: 90)
        clock.advance(1)
        _ = await scorer.addIndicator(.init(name: "connects_raw_ip", weight: 2),
                                      forProcess: 90, path: path, processStart: laterStart)
        #expect(await scorer.score(forPid: 90, path: path) < 2.5, "a fresh generation")
        #expect(await scorer.lifecycleInvariantFailures().isEmpty)
        // Still marked exited, so the queued exit drops it after the grace.
        clock.advance(601)
        await scorer.processExited(pid: 91)
        #expect(await scorer.score(forPid: 90, path: path) == 0)
        #expect(await scorer.lifecycleInvariantFailures().isEmpty)
    }

    @Test("the emitter passes the scored process's start time on every path")
    func emitterPassesStartTime() throws {
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let emitter = try String(
            contentsOf: root.appendingPathComponent("Sources/MacCrabAgentKit/BehaviorScoreAlertEmitter.swift"),
            encoding: .utf8)
        #expect(emitter.components(separatedBy: "processStart: processStart(of: event, pid: pid)").count - 1 == 2)
        let ruleMatch = try #require(emitter.range(of: "static func recordRuleMatch("))
        #expect(emitter[ruleMatch.upperBound...].prefix(600).contains("processStart: event.process.startTime"))

        let started = Date(timeIntervalSince1970: 1_700_000_000)
        let process = MacCrabCore.ProcessInfo(
            pid: 5, ppid: 1, rpid: 1, name: "sh", executable: "/bin/sh", commandLine: "sh",
            args: ["sh"], workingDirectory: "/", userId: 501, userName: "u", groupId: 20,
            startTime: started)
        let event = Event(eventCategory: .process, eventType: .start, eventAction: "exec", process: process)
        #expect(BehaviorScoreAlertEmitter.processStart(of: event, pid: 5) == started)
        #expect(BehaviorScoreAlertEmitter.processStart(of: event, pid: 6) == nil,
                "another pid's event does not date the scored process")
        #expect(BehaviorScoreAlertEmitter.processStart(of: nil, pid: 5) == nil)
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
