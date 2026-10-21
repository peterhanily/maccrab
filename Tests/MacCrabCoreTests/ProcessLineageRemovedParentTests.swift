import Foundation
import Testing
@testable import MacCrabCore

/// A removed node's children keep it as their parent, so sequence
/// `descendant` steps bound to an exited dropper still match after the
/// table evicts it; they move to launchd only when another process takes
/// the pid.
@Suite("ProcessLineage keeps a removed parent's edge until its pid is reused")
struct ProcessLineageRemovedParentTests {
    /// launchd, an exited postinstall shell (100) and its detached child (101);
    /// two more inserts push the shell out through the exit queue.
    private func evictedDropper() async -> ProcessLineage {
        let lineage = ProcessLineage(maxProcessCount: 4)
        let start = Date(timeIntervalSince1970: 1_000)
        await lineage.recordProcess(pid: 1, ppid: 0, path: "/sbin/launchd", name: "launchd", startTime: start)
        await lineage.recordProcess(pid: 100, ppid: 1, path: "/bin/sh", name: "sh", startTime: start)
        await lineage.recordProcess(pid: 101, ppid: 100, path: "/tmp/rat", name: "rat", startTime: start)
        await lineage.recordExit(pid: 100)
        await lineage.recordProcess(pid: 102, ppid: 1, path: "/usr/bin/true", name: "true", startTime: start)
        await lineage.recordProcess(pid: 103, ppid: 1, path: "/usr/bin/true", name: "true", startTime: start)
        return lineage
    }

    @Test("an exited parent evicted under the cap is still its child's ancestor")
    func evictedExitedParentKeepsDescendantEdge() async {
        let lineage = await evictedDropper()
        #expect(await !lineage.contains(pid: 100))
        #expect(await lineage.isDescendant(101, of: 100))
        let snapshot = await lineage.relationshipSnapshot(for: [101, 100])
        #expect(snapshot.isDescendant(101, of: 100))
    }

    @Test("a new process taking the removed parent's pid does not adopt its children")
    func reuseReleasesChildren() async {
        let lineage = await evictedDropper()
        // The insert below is over the cap again; let it evict a known exit.
        await lineage.recordExit(pid: 102)
        await lineage.recordProcess(pid: 100, ppid: 1, path: "/usr/local/bin/claude", name: "claude",
                                    startTime: Date(timeIntervalSince1970: 1_600))
        #expect(await !lineage.isDescendant(101, of: 100))
        #expect(await lineage.ancestors(of: 101).map(\.executable) == ["/sbin/launchd"])
    }

    @Test("the evicted parent's own late event, with its start time, keeps the edge")
    func lateEventKeepsDescendantEdge() async {
        let lineage = await evictedDropper()
        await lineage.recordExit(pid: 102)
        // The dropper's lagging file event re-records it with its ES start time.
        await lineage.recordProcess(pid: 100, ppid: 1, path: "/bin/sh", name: "sh",
                                    startTime: Date(timeIntervalSince1970: 1_000))
        #expect(await lineage.isDescendant(101, of: 100))
        #expect(await lineage.ancestors(of: 101).map(\.executable) == ["/bin/sh", "/sbin/launchd"])
    }

    @Test("an observation-time sighting of an evicted parent keeps the edge; a later birth releases it")
    func sightingKeepsRemovedParentEdge() async {
        let lineage = await evictedDropper()
        await lineage.recordExit(pid: 102)
        // A network poll saw the dropper before it exited; its event, enriched
        // late, starts the process at the poll time, not at its birth.
        await lineage.recordProcess(pid: 100, ppid: 1, path: "/bin/sh", name: "sh",
                                    startTime: Date(timeIntervalSince1970: 1_500), startTimeIsBirth: false)
        #expect(await lineage.isDescendant(101, of: 100))
        // An Endpoint Security birth later than that is a new process.
        await lineage.recordProcess(pid: 100, ppid: 1, path: "/usr/local/bin/claude", name: "claude",
                                    startTime: Date(timeIntervalSince1970: 1_600))
        #expect(await !lineage.isDescendant(101, of: 100))
    }

    @Test("a new process's own sighting before its birth still releases the removed parent's children")
    func sightingBeforeBirthReleasesChildren() async {
        let lineage = await evictedDropper()
        await lineage.recordExit(pid: 102)
        // claude takes the dropper's pid at 1,500; its network event (poll
        // time 1,600) is enriched before its Endpoint Security birth.
        await lineage.recordProcess(pid: 100, ppid: 1, path: "/usr/local/bin/claude", name: "claude",
                                    startTime: Date(timeIntervalSince1970: 1_600), startTimeIsBirth: false)
        await lineage.recordProcess(pid: 100, ppid: 1, path: "/usr/local/bin/claude", name: "claude",
                                    startTime: Date(timeIntervalSince1970: 1_500))
        #expect(await !lineage.isDescendant(101, of: 100))
        #expect(await lineage.ancestors(of: 101).map(\.executable) == ["/sbin/launchd"])
    }

    @Test("a sighted node removed with children keeps them when its own birth arrives")
    func removedSightingKeepsChildrenAtBirth() async {
        let lineage = ProcessLineage(maxProcessCount: 4)
        let birth = Date(timeIntervalSince1970: 1_000)
        await lineage.recordProcess(pid: 1, ppid: 0, path: "/sbin/launchd", name: "launchd", startTime: birth)
        // First seen by a network poll an hour after its birth.
        await lineage.recordProcessIfAbsent(pid: 600, ppid: 1, path: "/usr/bin/python3", name: "python3",
                                            startTime: birth.addingTimeInterval(3_600), startTimeIsBirth: false)
        await lineage.recordProcess(pid: 601, ppid: 600, path: "/bin/sh", name: "sh",
                                    startTime: birth.addingTimeInterval(3_700))
        await lineage.recordExit(pid: 600)
        await lineage.recordProcess(pid: 602, ppid: 1, path: "/usr/bin/true", name: "true", startTime: birth)
        await lineage.recordProcess(pid: 603, ppid: 1, path: "/usr/bin/true", name: "true", startTime: birth)
        #expect(await !lineage.contains(pid: 600))
        // Its own late Endpoint Security event carries the earlier kernel
        // birth: the same process, so the child keeps its parent.
        await lineage.recordExit(pid: 602)
        await lineage.recordProcess(pid: 600, ppid: 1, path: "/usr/bin/python3", name: "python3", startTime: birth)
        #expect(await lineage.isDescendant(601, of: 600))
    }

    @Test("a node first seen by another source keeps its children when it execs")
    func execAfterSightingKeepsChildren() async {
        let lineage = ProcessLineage(maxProcessCount: 10)
        let birth = Date(timeIntervalSince1970: 1_000)
        await lineage.recordProcess(pid: 1, ppid: 0, path: "/sbin/launchd", name: "launchd", startTime: birth)
        // First recorded from a network poll, an hour after its birth.
        await lineage.recordProcessIfAbsent(pid: 400, ppid: 1, path: "/usr/bin/python3", name: "python3",
                                            startTime: birth.addingTimeInterval(3_600), startTimeIsBirth: false)
        await lineage.recordProcess(pid: 401, ppid: 400, path: "/bin/sh", name: "sh",
                                    startTime: birth.addingTimeInterval(3_700))
        // Its exec reports the kernel birth time, earlier than the sighting.
        await lineage.recordProcess(pid: 400, ppid: 1, path: "/usr/local/bin/node", name: "node", startTime: birth)
        #expect(await lineage.isDescendant(401, of: 400))
    }

    @Test("recording an absent process never overwrites one recorded in between")
    func recordIfAbsentKeepsExistingNode() async throws {
        let lineage = ProcessLineage(maxProcessCount: 10)
        let start = Date(timeIntervalSince1970: 1_000)
        await lineage.recordProcess(pid: 500, ppid: 1, path: "/usr/local/bin/node", name: "node", startTime: start,
                                    commandLine: "node /srv/server-filesystem/dist/index.js /tmp")
        await lineage.recordProcessIfAbsent(pid: 500, ppid: 1, path: "/usr/local/bin/node", name: "node",
                                            startTime: start, commandLine: "")
        #expect(await lineage.commandLine(of: 500) == "node /srv/server-filesystem/dist/index.js /tmp")
        await lineage.recordProcessIfAbsent(pid: 501, ppid: 500, path: "/bin/sh", name: "sh", startTime: start)
        #expect(await lineage.contains(pid: 501))
        // The enricher's untracked-process branch uses the one-turn form and
        // tells a kernel birth time from a sighting.
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let enricher = try String(contentsOf: root.appendingPathComponent("Sources/MacCrabCore/Enrichment/EventEnricher.swift"),
                                  encoding: .utf8)
        let branch = try #require(enricher.range(of: "private func updateLineage(for event: Event)"))
        let body = enricher[branch.lowerBound...].prefix(2_400)
        #expect(body.contains("await lineage.recordProcessIfAbsent("))
        #expect(body.contains("startTimeIsBirth: proc.auditIdentity != nil"))
        #expect(!body.contains("lineage.contains(pid:"))
    }

    @Test("a process reusing a running node's pid does not adopt its children")
    func reusedRunningPidReleasesChildren() async {
        let lineage = ProcessLineage(maxProcessCount: 10)
        let start = Date(timeIntervalSince1970: 1_000)
        await lineage.recordProcess(pid: 1, ppid: 0, path: "/sbin/launchd", name: "launchd", startTime: start)
        // Its exit is muted, so the node stays running after it quits.
        await lineage.recordProcess(pid: 300, ppid: 1, path: "/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal",
                                    name: "Terminal", startTime: start.addingTimeInterval(1))
        await lineage.recordProcess(pid: 301, ppid: 300, path: "/bin/zsh", name: "zsh",
                                    startTime: start.addingTimeInterval(2))
        await lineage.recordProcess(pid: 300, ppid: 1, path: "/usr/local/bin/claude", name: "claude",
                                    startTime: start.addingTimeInterval(600))
        #expect(await !lineage.isDescendant(301, of: 300))
        #expect(await lineage.ancestors(of: 301).map(\.executable) == ["/sbin/launchd"])
    }

    @Test("a running parent evicted under the cap keeps its children when it execs")
    func evictedRunningParentKeepsChildrenAcrossExec() async {
        let lineage = ProcessLineage(maxProcessCount: 3)
        let start = Date(timeIntervalSince1970: 1_000)
        await lineage.recordProcess(pid: 200, ppid: 1, path: "/bin/zsh", name: "zsh", startTime: start)
        await lineage.recordProcess(pid: 201, ppid: 200, path: "/usr/bin/vim", name: "vim",
                                    startTime: start.addingTimeInterval(10))
        await lineage.recordProcess(pid: 202, ppid: 1, path: "/usr/bin/a", name: "a",
                                    startTime: start.addingTimeInterval(20))
        // Over the cap with no recorded exit: the oldest running node goes.
        await lineage.recordProcess(pid: 203, ppid: 1, path: "/usr/bin/b", name: "b",
                                    startTime: start.addingTimeInterval(30))
        #expect(await !lineage.contains(pid: 200))
        await lineage.recordExit(pid: 202)
        // The same process execs: same pid, same start time.
        await lineage.recordProcess(pid: 200, ppid: 1, path: "/usr/local/bin/node", name: "node", startTime: start)
        #expect(await lineage.contains(pid: 200))
        #expect(await lineage.isDescendant(201, of: 200))
        #expect(await lineage.ancestors(of: 201).map(\.executable) == ["/usr/local/bin/node"])
    }
}

/// ES mutes exits acted by /System/ images, so a spawn loop of short-lived
/// /System/ binaries leaves nodes that never record an exit.
@Suite("ProcessLineage evicts exit-unobservable nodes before live processes")
struct ProcessLineageUnobservedExitEvictionTests {
    private final class Liveness: @unchecked Sendable {
        private let lock = NSLock()
        private var checks = 0
        private let isDead: @Sendable (pid_t) -> Bool
        init(isDead: @escaping @Sendable (pid_t) -> Bool) { self.isDead = isDead }
        func isRunning(_ pid: pid_t) -> Bool {
            lock.lock(); checks += 1; lock.unlock()
            return !isDead(pid)
        }
        var count: Int { lock.lock(); defer { lock.unlock() }; return checks }
        func reset() { lock.lock(); checks = 0; lock.unlock() }
    }

    @Test("a /System/ spawn loop evicts dead nodes, not launchd, the shell or the agent")
    func vanishedSystemNodesGoFirst() async {
        let liveness = Liveness(isDead: { $0 >= 1_000 })
        let lineage = ProcessLineage(maxProcessCount: 8, processIsRunning: { pid, _ in liveness.isRunning(pid) })
        let boot = Date(timeIntervalSince1970: 1_000)
        await lineage.recordProcess(pid: 1, ppid: 0, path: "/sbin/launchd", name: "launchd", startTime: boot)
        await lineage.recordProcess(pid: 50, ppid: 1, path: "/bin/zsh", name: "zsh", startTime: boot.addingTimeInterval(1))
        await lineage.recordProcess(pid: 60, ppid: 50, path: "/usr/local/bin/claude", name: "claude",
                                    startTime: boot.addingTimeInterval(2))
        for index in 0..<200 {
            await lineage.recordProcess(
                pid: pid_t(1_000 + index), ppid: 60,
                path: "/System/Library/Frameworks/JavaScriptCore.framework/Helpers/jsc", name: "jsc",
                startTime: boot.addingTimeInterval(10 + Double(index)))
        }
        #expect(await lineage.contains(pid: 1))
        #expect(await lineage.contains(pid: 50))
        #expect(await lineage.contains(pid: 60))
        #expect(await lineage.ancestors(of: 1_199).map(\.name) == ["claude", "zsh", "launchd"])
    }

    @Test("eviction rotates at most 64 young live candidates, then takes the oldest running process")
    func livenessChecksAreBounded() async {
        let liveness = Liveness(isDead: { _ in false })
        let lineage = ProcessLineage(maxProcessCount: 200, processIsRunning: { pid, _ in liveness.isRunning(pid) })
        // Younger than the liveness grace: they may still exit, so they stay queued.
        let now = Date()
        for index in 0..<200 {
            await lineage.recordProcess(pid: pid_t(2_000 + index), ppid: 1, path: "/System/Library/CoreServices/x",
                                        name: "x", startTime: now.addingTimeInterval(Double(index) / 1_000))
        }
        liveness.reset()
        await lineage.recordProcess(pid: 9_000, ppid: 1, path: "/usr/bin/true", name: "true",
                                    startTime: now.addingTimeInterval(1))
        #expect(liveness.count == 64)
        #expect(await !lineage.contains(pid: 2_000))
        #expect(await lineage.nodeCount == 200)
    }

    @Test("long-lived /System/ processes leave the queue instead of costing launchd its slot")
    func longLivedSystemProcessesAreDequeued() async {
        let liveness = Liveness(isDead: { $0 >= 5_000 })
        let lineage = ProcessLineage(maxProcessCount: 100, processIsRunning: { pid, _ in liveness.isRunning(pid) })
        let now = Date()
        await lineage.recordProcess(pid: 1, ppid: 0, path: "/sbin/launchd", name: "launchd",
                                    startTime: now.addingTimeInterval(-7_200))
        await lineage.recordProcess(pid: 50, ppid: 1, path: "/bin/zsh", name: "zsh",
                                    startTime: now.addingTimeInterval(-7_000))
        // A session's long-lived /System/ processes (WindowServer, Dock, Terminal…).
        for index in 0..<80 {
            await lineage.recordProcess(pid: pid_t(2_000 + index), ppid: 1, path: "/System/Library/CoreServices/Dock.app/x",
                                        name: "x", startTime: now.addingTimeInterval(-3_600 + Double(index)))
        }
        // Then a spawn loop of short-lived /System/ binaries, well past the cap.
        for index in 0..<300 {
            if index == 100 { liveness.reset() }
            await lineage.recordProcess(pid: pid_t(5_000 + index), ppid: 50,
                                        path: "/System/Library/Frameworks/JavaScriptCore.framework/Helpers/jsc",
                                        name: "jsc", startTime: now)
        }
        #expect(await lineage.contains(pid: 1))
        #expect(await lineage.contains(pid: 50))
        // Each long-lived process was checked once, then dropped: later
        // evictions find a dead node at the head of the queue.
        #expect(liveness.count <= 200, "\(liveness.count) checks for 200 inserts")
    }

    @Test("the queue stays bounded while recorded exits serve every eviction")
    func unobservedQueueIsBounded() async {
        let lineage = ProcessLineage(maxProcessCount: 8, processIsRunning: { _, _ in true })
        let now = Date()
        for index in 0..<3_000 {
            let pid = pid_t(10_000 + index)
            await lineage.recordProcess(pid: pid, ppid: 1, path: "/System/Library/CoreServices/x",
                                        name: "x", startTime: now)
            await lineage.recordExit(pid: pid)
        }
        #expect(await lineage.unobservedExitQueueLength <= 2 * 8 + 1_024)
    }
}
