// ProcessLineagePerfTests.swift
// Tier-B per-event perf batch — parity + behavioral coverage for two
// ProcessLineage/EventEnricher changes:
//
//   #10  ancestorsAndParentInfo(of:) folds the former two separate actor
//        calls (ancestors + parentInfo) into one hop. Parity requirement:
//        the combined result is byte-identical to calling the two APIs
//        separately.
//
//   #16  ancestors(of:) is memoized per pid, with the whole memo cleared on
//        every structural graph mutation (recordProcess add/overwrite,
//        removeNode via evict/prune). Detection-exactness requirement: a
//        pid that exits and is REUSED — and, more generally, any pid whose
//        ancestor set changes (parent added later, ancestor pruned) — must
//        return the NEW chain, never a stale memoized one.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("ProcessLineage: Tier-B #10 fold parity")
struct ProcessLineageFoldParityTests {

    /// Assert the combined accessor returns exactly what the two separate
    /// calls return, field for field, for `pid`.
    private func assertParity(_ lineage: ProcessLineage, pid: pid_t) async {
        let separateAncestors = await lineage.ancestors(of: pid)
        let separateParent = await lineage.parentInfo(of: pid)
        let combined = await lineage.ancestorsAndParentInfo(of: pid)

        #expect(combined.ancestors == separateAncestors)
        #expect(combined.parentInfo?.commandLine == separateParent?.commandLine)
        #expect(combined.parentInfo?.signerType == separateParent?.signerType)
        #expect(combined.parentInfo?.path == separateParent?.path)
        // Presence must match too (both nil or both non-nil).
        #expect((combined.parentInfo == nil) == (separateParent == nil))
    }

    @Test("Combined == separate for a full ancestor chain with parent fields")
    func parityFullChain() async {
        let lineage = ProcessLineage()
        await lineage.recordProcess(pid: 1, ppid: 0, path: "/sbin/launchd", name: "launchd", startTime: Date(), commandLine: "/sbin/launchd", signerType: "apple")
        await lineage.recordProcess(pid: 50, ppid: 1, path: "/bin/zsh", name: "zsh", startTime: Date(), commandLine: "-zsh", signerType: "apple")
        await lineage.recordProcess(pid: 100, ppid: 50, path: "/usr/bin/curl", name: "curl", startTime: Date(), commandLine: "curl http://x", signerType: "devId")

        await assertParity(lineage, pid: 100)   // parent zsh has cmdline + signer
        await assertParity(lineage, pid: 50)     // parent launchd
        await assertParity(lineage, pid: 1)      // parent (0) not tracked → parentInfo nil
    }

    @Test("Combined == separate when the parent has an empty command line")
    func parityEmptyParentCmdline() async {
        let lineage = ProcessLineage()
        // Parent recorded with default (empty) commandLine → parentInfo.commandLine must be nil.
        await lineage.recordProcess(pid: 200, ppid: 0, path: "/bin/parent", name: "parent", startTime: Date())
        await lineage.recordProcess(pid: 201, ppid: 200, path: "/bin/child", name: "child", startTime: Date())

        let combined = await lineage.ancestorsAndParentInfo(of: 201)
        #expect(combined.parentInfo != nil)                 // parent node exists
        #expect(combined.parentInfo?.commandLine == nil)    // but its cmdline was empty
        await assertParity(lineage, pid: 201)
    }

    @Test("Combined == separate for an untracked pid (empty + nil)")
    func parityUntracked() async {
        let lineage = ProcessLineage()
        let combined = await lineage.ancestorsAndParentInfo(of: 999)
        #expect(combined.ancestors.isEmpty)
        #expect(combined.parentInfo == nil)
        await assertParity(lineage, pid: 999)
    }

    @Test("Combined == separate for a tracked pid whose parent is untracked")
    func parityOrphanParent() async {
        let lineage = ProcessLineage()
        // pid 300 tracked, ppid 42 never recorded → ancestors empty, parentInfo nil.
        await lineage.recordProcess(pid: 300, ppid: 42, path: "/bin/orphan", name: "orphan", startTime: Date())
        let combined = await lineage.ancestorsAndParentInfo(of: 300)
        #expect(combined.ancestors.isEmpty)
        #expect(combined.parentInfo == nil)
        await assertParity(lineage, pid: 300)
    }
}

@Suite("ProcessLineage: Tier-B #16 ancestor memo invalidation")
struct ProcessLineageMemoTests {

    private func names(_ ancestors: [ProcessAncestor]) -> [String] { ancestors.map(\.name) }

    @Test("Repeated queries return an identical chain (memo hit is transparent)")
    func repeatedQueryStable() async {
        let lineage = ProcessLineage()
        await lineage.recordProcess(pid: 1, ppid: 0, path: "/sbin/launchd", name: "launchd", startTime: Date())
        await lineage.recordProcess(pid: 50, ppid: 1, path: "/bin/zsh", name: "zsh", startTime: Date())
        await lineage.recordProcess(pid: 100, ppid: 50, path: "/usr/bin/curl", name: "curl", startTime: Date())

        let first = await lineage.ancestors(of: 100)
        let second = await lineage.ancestors(of: 100)   // served from memo
        #expect(first == second)
        #expect(names(first) == ["zsh", "launchd"])
    }

    @Test("A pid that exits and is REUSED returns the NEW chain, not the memoized one")
    func pidReuseAfterExitInvalidatesMemo() async {
        let lineage = ProcessLineage()
        await lineage.recordProcess(pid: 1, ppid: 0, path: "/sbin/launchd", name: "launchd", startTime: Date())
        await lineage.recordProcess(pid: 50, ppid: 1, path: "/bin/oldparent", name: "oldparent", startTime: Date())
        await lineage.recordProcess(pid: 100, ppid: 50, path: "/bin/child", name: "child", startTime: Date())

        // Prime the memo for pid 100 under its original parent.
        let original = await lineage.ancestors(of: 100)
        #expect(names(original) == ["oldparent", "launchd"])

        // Process 100 exits. Exit alone must NOT change ancestors (node stays).
        await lineage.recordExit(pid: 100)
        let afterExit = await lineage.ancestors(of: 100)
        #expect(names(afterExit) == ["oldparent", "launchd"])

        // pid 100 is REUSED by a brand-new process, now a direct child of launchd.
        await lineage.recordProcess(pid: 100, ppid: 1, path: "/bin/newproc", name: "newproc", startTime: Date())
        let afterReuse = await lineage.ancestors(of: 100)
        // MUST be the new single-hop chain, never the stale ["oldparent","launchd"].
        #expect(names(afterReuse) == ["launchd"])
    }

    @Test("A parent recorded AFTER its child invalidates the child's memoized empty chain")
    func parentAddedLaterInvalidatesDescendant() async {
        let lineage = ProcessLineage()
        // Child seen first; its parent (50) is not yet tracked → empty chain.
        await lineage.recordProcess(pid: 100, ppid: 50, path: "/bin/child", name: "child", startTime: Date())
        let empty = await lineage.ancestors(of: 100)
        #expect(empty.isEmpty)   // memoized empty

        // Now the parent (and grandparent) arrive.
        await lineage.recordProcess(pid: 1, ppid: 0, path: "/sbin/launchd", name: "launchd", startTime: Date())
        await lineage.recordProcess(pid: 50, ppid: 1, path: "/bin/parent", name: "parent", startTime: Date())

        // The child's chain must now be rebuilt — NOT the stale empty memo.
        let filled = await lineage.ancestors(of: 100)
        #expect(names(filled) == ["parent", "launchd"])
    }

    @Test("Pruning an ancestor shortens a descendant's chain (memo invalidated on removeNode)")
    func prunedAncestorInvalidatesDescendant() async {
        let lineage = ProcessLineage(retentionWindow: 0.1)
        await lineage.recordProcess(pid: 1, ppid: 0, path: "/sbin/launchd", name: "launchd", startTime: Date())
        await lineage.recordProcess(pid: 50, ppid: 1, path: "/bin/parent", name: "parent", startTime: Date())
        await lineage.recordProcess(pid: 100, ppid: 50, path: "/bin/child", name: "child", startTime: Date())

        // Prime the memo with the full chain.
        let full = await lineage.ancestors(of: 100)
        #expect(names(full) == ["parent", "launchd"])

        // Parent 50 exits and ages out; prune removes its node.
        await lineage.recordExit(pid: 50)
        try? await Task.sleep(nanoseconds: 200_000_000)
        await lineage.prune()
        #expect(await !lineage.contains(pid: 50))

        // The child was reparented to launchd when its exited parent was
        // removed, as the kernel does → ["launchd"], NOT the stale
        // ["parent","launchd"] memo.
        let afterPrune = await lineage.ancestors(of: 100)
        #expect(names(afterPrune) == ["launchd"])
    }

    @Test("Eviction of an ancestor under cap pressure invalidates descendant memo")
    func evictedAncestorInvalidatesDescendant() async {
        // Small cap so a later insert forces LRU eviction of an exited node.
        let lineage = ProcessLineage(retentionWindow: 3600, maxProcessCount: 3)
        await lineage.recordProcess(pid: 1, ppid: 0, path: "/sbin/launchd", name: "launchd", startTime: Date(timeIntervalSince1970: 1))
        await lineage.recordProcess(pid: 50, ppid: 1, path: "/bin/parent", name: "parent", startTime: Date(timeIntervalSince1970: 2))
        await lineage.recordProcess(pid: 100, ppid: 50, path: "/bin/child", name: "child", startTime: Date(timeIntervalSince1970: 3))

        // Prime memo for the child.
        #expect(names(await lineage.ancestors(of: 100)) == ["parent", "launchd"])

        // Mark launchd exited so it is the eviction-preferred victim, then push
        // over the cap so eviction fires.
        await lineage.recordExit(pid: 1)
        await lineage.recordProcess(pid: 200, ppid: 0, path: "/bin/other", name: "other", startTime: Date(timeIntervalSince1970: 4))
        #expect(await !lineage.contains(pid: 1))

        // launchd is gone → the child's chain now ends at parent (walk stops
        // when launchd's node is missing). Must NOT be the stale 2-entry memo.
        let afterEvict = await lineage.ancestors(of: 100)
        #expect(names(afterEvict) == ["parent"])
    }
}

@Suite("EventEnricher: Tier-B #10 fold preserves parent enrichment")
struct EventEnricherFoldTests {

    private func makeProcess(pid: Int32, ppid: Int32) -> MacCrabCore.ProcessInfo {
        MacCrabCore.ProcessInfo(
            pid: pid,
            ppid: ppid,
            rpid: ppid,
            name: "child",
            executable: "/bin/child",
            commandLine: "/bin/child",
            args: ["/bin/child"],
            workingDirectory: "/tmp",
            userId: UInt32(getuid()),
            userName: "tester",
            groupId: 20,
            startTime: Date()
        )
    }

    @Test("parent.commandline + ParentSignerType are populated via the folded accessor")
    func parentEnrichmentFlows() async {
        let lineage = ProcessLineage()
        // Pre-register the parent with a command line and signer type.
        await lineage.recordProcess(
            pid: 500, ppid: 1,
            path: "/bin/parentproc", name: "parentproc",
            startTime: Date(),
            commandLine: "/bin/parentproc --serve",
            signerType: "apple"
        )
        let enricher = EventEnricher(lineage: lineage)

        let event = Event(
            eventCategory: .process,
            eventType: .start,
            eventAction: "exec",
            process: makeProcess(pid: 600, ppid: 500)
        )
        let enriched = await enricher.enrich(event)

        // These two enrichments come straight from the folded parentInfo.
        #expect(enriched.enrichments["parent.commandline"] == "/bin/parentproc --serve")
        #expect(enriched.enrichments["ParentSignerType"] == "apple")
        // Ancestors (the other half of the fold) still attach the parent.
        #expect(enriched.process.ancestors.contains { $0.name == "parentproc" })
    }
}

@Suite("ProcessLineage exit-order eviction")
struct ProcessLineageExitOrderEvictionTests {
    @Test("at the cap the earliest exit is evicted first; reused and pruned pids are skipped")
    func evictsEarliestExit() async {
        let lineage = ProcessLineage(retentionWindow: 3600, maxProcessCount: 4)
        let start = Date()
        for pid in Int32(1)...4 {
            await lineage.recordProcess(pid: pid, ppid: 0, path: "/bin/p\(pid)", name: "p\(pid)", startTime: start)
        }
        await lineage.recordExit(pid: 3)
        await lineage.recordExit(pid: 1)
        await lineage.recordExit(pid: 2)
        // pid 3 is reused by a running process: its exit entry is stale.
        await lineage.recordProcess(pid: 3, ppid: 0, path: "/bin/new3", name: "new3", startTime: start)

        await lineage.recordProcess(pid: 5, ppid: 0, path: "/bin/p5", name: "p5", startTime: start)
        #expect(await lineage.path(of: 1) == nil, "the earliest live exit goes first")
        #expect(await lineage.path(of: 3) == "/bin/new3")
        await lineage.recordProcess(pid: 6, ppid: 0, path: "/bin/p6", name: "p6", startTime: start)
        #expect(await lineage.path(of: 2) == nil)
        // No exited node left: the oldest running process goes.
        await lineage.recordProcess(pid: 7, ppid: 0, path: "/bin/p7", name: "p7",
                                    startTime: start.addingTimeInterval(10))
        #expect(await lineage.nodeCount == 4)
        #expect(await lineage.path(of: 7) == "/bin/p7")
    }
}

@Suite("ProcessLineage pid reuse")
struct ProcessLineagePidReuseTests {
    @Test("children of an exited process do not inherit the process that reuses its pid")
    func reusedPidDoesNotAdoptOldChildren() async {
        let lineage = ProcessLineage()
        let start = Date()
        await lineage.recordProcess(pid: 1, ppid: 0, path: "/sbin/launchd", name: "launchd", startTime: start)
        await lineage.recordProcess(pid: 100, ppid: 1, path: "/bin/zsh", name: "zsh", startTime: start)
        await lineage.recordProcess(pid: 200, ppid: 100, path: "/usr/bin/caffeinate", name: "caffeinate", startTime: start)
        #expect(await lineage.ancestors(of: 200).map(\.pid) == [100, 1])

        await lineage.recordExit(pid: 100)
        await lineage.recordProcess(pid: 100, ppid: 1, path: "/usr/local/bin/claude", name: "claude",
                                    startTime: start.addingTimeInterval(60))
        #expect(await lineage.ancestors(of: 200).map(\.executable) == ["/sbin/launchd"])

        // An exec of a live process (no exit seen) keeps its children.
        await lineage.recordProcess(pid: 300, ppid: 100, path: "/bin/sh", name: "sh", startTime: start)
        await lineage.recordProcess(pid: 100, ppid: 1, path: "/usr/local/bin/node", name: "node",
                                    startTime: start.addingTimeInterval(60))
        #expect(await lineage.ancestors(of: 300).first?.executable == "/usr/local/bin/node")
    }

    @Test("a pid reused after its exited process was pruned does not adopt the old children")
    func reuseAfterPruneDoesNotAdoptOldChildren() async {
        let lineage = ProcessLineage(retentionWindow: 0)
        let start = Date()
        await lineage.recordProcess(pid: 1, ppid: 0, path: "/sbin/launchd", name: "launchd", startTime: start)
        await lineage.recordProcess(pid: 100, ppid: 1, path: "/bin/zsh", name: "zsh", startTime: start)
        await lineage.recordProcess(pid: 200, ppid: 100, path: "/usr/bin/caffeinate", name: "caffeinate", startTime: start)
        await lineage.recordExit(pid: 100)
        try? await Task.sleep(for: .milliseconds(10))
        await lineage.prune()
        #expect(await lineage.path(of: 100) == nil)
        await lineage.recordProcess(pid: 100, ppid: 1, path: "/usr/local/bin/claude", name: "claude",
                                    startTime: start.addingTimeInterval(3_600))
        #expect(await lineage.ancestors(of: 200).map(\.executable) == ["/sbin/launchd"])
    }
}

@Suite("ProcessLineage exit-order queue compaction")
struct ProcessLineageExitOrderCompactionTests {
    @Test("stale exit entries are compacted and eviction still takes the earliest live exit")
    func compactionKeepsEvictionExact() async {
        let lineage = ProcessLineage(retentionWindow: 3_600, maxProcessCount: 4)
        let start = Date()
        // One pid exiting and being re-recorded 1,200 times leaves stale entries
        // past the rebuild bound (2 * 4 + 1,024).
        for _ in 0..<1_200 {
            await lineage.recordProcess(pid: 50, ppid: 0, path: "/bin/churn", name: "churn", startTime: start)
            await lineage.recordExit(pid: 50)
        }
        await lineage.recordProcess(pid: 60, ppid: 0, path: "/bin/a", name: "a", startTime: start)
        await lineage.recordExit(pid: 60)
        await lineage.recordProcess(pid: 70, ppid: 0, path: "/bin/b", name: "b", startTime: start)
        await lineage.recordProcess(pid: 80, ppid: 0, path: "/bin/c", name: "c", startTime: start)
        // At the cap; the next insert evicts the earliest live exit: pid 50.
        await lineage.recordProcess(pid: 90, ppid: 0, path: "/bin/d", name: "d", startTime: start)
        #expect(await lineage.path(of: 50) == nil)
        #expect(await lineage.path(of: 60) == "/bin/a")
        await lineage.recordProcess(pid: 91, ppid: 0, path: "/bin/e", name: "e", startTime: start)
        #expect(await lineage.path(of: 60) == nil)
        #expect(await lineage.nodeCount == 4)
    }
}

@Suite("ProcessLineage exits that never arrive")
struct ProcessLineageLivenessTests {
    private final class DeadPids: @unchecked Sendable {
        private let lock = NSLock()
        private var pids: Set<pid_t> = []
        func kill(_ pid: pid_t) { lock.lock(); pids.insert(pid); lock.unlock() }
        func isRunning(_ pid: pid_t) -> Bool { lock.lock(); defer { lock.unlock() }; return !pids.contains(pid) }
    }

    @Test("a vanished process is marked exited, so its children are not adopted by a pid reuse")
    func vanishedParentReleasesChildren() async throws {
        let dead = DeadPids()
        let lineage = ProcessLineage(retentionWindow: 0.05, processIsRunning: { pid, _ in dead.isRunning(pid) })
        let past = Date(timeIntervalSinceNow: -60)
        await lineage.recordProcess(pid: 1, ppid: 0, path: "/sbin/launchd", name: "launchd", startTime: past)
        await lineage.recordProcess(pid: 300, ppid: 1, path: "/System/Library/Frameworks/X.framework/x",
                                    name: "x", startTime: past)
        await lineage.recordProcess(pid: 301, ppid: 300, path: "/usr/bin/tool", name: "tool", startTime: past)
        // The /System/ parent exits; its exit is muted and never recorded.
        dead.kill(300)
        await lineage.prune()   // marks 300 exited
        try await Task.sleep(nanoseconds: 100_000_000)
        await lineage.prune()   // retention removes it and reparents 301
        #expect(await !lineage.contains(pid: 300))
        await lineage.recordProcess(pid: 300, ppid: 1, path: "/usr/local/bin/claude", name: "claude", startTime: Date())
        #expect(await lineage.ancestors(of: 301).map(\.executable) == ["/sbin/launchd"])
    }

    @Test("a live process, a just-started one and launchd are never marked exited")
    func liveProcessesStay() async {
        let dead = DeadPids()
        dead.kill(400)
        dead.kill(1)
        let lineage = ProcessLineage(retentionWindow: 0, processIsRunning: { pid, _ in dead.isRunning(pid) })
        await lineage.recordProcess(pid: 1, ppid: 0, path: "/sbin/launchd", name: "launchd",
                                    startTime: Date(timeIntervalSinceNow: -60))
        await lineage.recordProcess(pid: 401, ppid: 1, path: "/bin/zsh", name: "zsh",
                                    startTime: Date(timeIntervalSinceNow: -60))
        await lineage.recordProcess(pid: 400, ppid: 1, path: "/bin/new", name: "new", startTime: Date())
        await lineage.prune()
        #expect(await lineage.contains(pid: 1))
        #expect(await lineage.contains(pid: 401))
        #expect(await lineage.contains(pid: 400), "inside the grace period")
    }

    @Test("the libproc probe sees this process and a reused pid as different starts")
    func liveProbe() {
        let me = Foundation.ProcessInfo.processInfo.processIdentifier
        #expect(ProcessLineage.liveProcessMatches(pid: me, startedAt: Date()))
        #expect(!ProcessLineage.liveProcessMatches(pid: me, startedAt: Date(timeIntervalSince1970: 0)),
                "a holder that started after the recorded start reused the pid")
        #expect(!ProcessLineage.liveProcessMatches(pid: 99_999_999, startedAt: Date()))
    }
}
