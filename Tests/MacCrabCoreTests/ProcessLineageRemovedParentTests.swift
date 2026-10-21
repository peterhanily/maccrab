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

    @Test("eviction checks at most 64 live candidates, then takes the oldest running process")
    func livenessChecksAreBounded() async {
        let liveness = Liveness(isDead: { _ in false })
        let lineage = ProcessLineage(maxProcessCount: 200, processIsRunning: { pid, _ in liveness.isRunning(pid) })
        let boot = Date(timeIntervalSince1970: 1_000)
        for index in 0..<200 {
            await lineage.recordProcess(pid: pid_t(2_000 + index), ppid: 1, path: "/System/Library/CoreServices/x",
                                        name: "x", startTime: boot.addingTimeInterval(Double(index)))
        }
        liveness.reset()
        await lineage.recordProcess(pid: 9_000, ppid: 1, path: "/usr/bin/true", name: "true",
                                    startTime: boot.addingTimeInterval(500))
        #expect(liveness.count == 64)
        #expect(await !lineage.contains(pid: 2_000))
        #expect(await lineage.nodeCount == 200)
    }
}
