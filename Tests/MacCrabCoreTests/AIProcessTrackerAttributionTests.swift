// AIProcessTrackerAttributionTests.swift
//
// v1.19 (S1-T5): genuine direct-ancestor AI attribution. Pre-fix
// `AIProcessTracker.isAIChild` trusted any pid present in `childToSession`
// (a recycled pid inherited the AI attribution) and would promote ANY
// ancestor matching an AI pattern to a session root with NO platform gate —
// so an Apple/SIP binary (XProtectRemediatorMRTv3) became a fake "Claude
// Code" root, minting false "Claude Code child process accessed credential"
// alerts. These tests pin: (a) genuine direct-ancestor lineage required,
// (b) Apple/SIP binaries are never an AI ROOT, (c) genuine agent children
// (osascript/curl/bash spawned by a real agent) are still attributed,
// (d) processExited evicts the child→session mapping.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("AIProcessTracker: genuine-lineage attribution (v1.19 S1-T5)")
struct AIProcessTrackerAttributionTests {

    private func ancestor(_ pid: Int32, _ exec: String) -> ProcessAncestor {
        ProcessAncestor(pid: pid, executable: exec, name: (exec as NSString).lastPathComponent)
    }

    // A real Claude Code root: non-Apple path matching the registry pattern.
    private let claudePath = "/Users/x/.local/bin/claude"

    @Test("Apple/SIP binary ancestor is NEVER promoted to an AI tool root")
    func appleBinaryNotAIRoot() async {
        let tracker = AIProcessTracker(lineage: ProcessLineage())
        // XProtect remediator under a SIP path that ALSO happens to share an
        // 'claude'-like substring would never match, but the real bug was the
        // remediator descending from / being attributed via a stale map. Here we
        // model an Apple binary whose path matches NO AI pattern: it must not be
        // a child, and crucially must not become a root.
        let xprotectAncestor = ancestor(
            900, "/Library/Apple/System/Library/CoreServices/XProtect.app/Contents/MacOS/XProtectRemediatorMRTv3")
        let result = await tracker.isAIChild(pid: 901, ancestors: [xprotectAncestor])
        #expect(result.isChild == false)
        #expect(await tracker.sessionCount == 0)
    }

    @Test("An Apple-path binary matching an AI substring is still NOT an AI root")
    func appleBinaryWithAISubstringNotRoot() async {
        let tracker = AIProcessTracker(lineage: ProcessLineage())
        // Defensive: even if an Apple/SIP-path binary's path contained an AI
        // pattern substring, the platform gate must reject it as a ROOT.
        let appleAncestor = ancestor(
            910, "/System/Library/PrivateFrameworks/codex-cli/helper")
        let result = await tracker.isAIChild(pid: 911, ancestors: [appleAncestor])
        #expect(result.isChild == false, "Apple/SIP-path binary must not be an AI root even with an AI substring")
        #expect(await tracker.sessionCount == 0)
    }

    @Test("A genuine non-Apple AI ancestor IS promoted to a root and attributes its child")
    func genuineAIAncestorAttributed() async {
        let tracker = AIProcessTracker(lineage: ProcessLineage())
        let aiAncestor = ancestor(1000, claudePath)
        let result = await tracker.isAIChild(pid: 1001, ancestors: [aiAncestor])
        #expect(result.isChild == true)
        #expect(result.toolType == .claudeCode)
        #expect(await tracker.sessionCount == 1)
    }

    @Test("A genuine agent child (osascript spawned by a real agent) is attributed")
    func genuineAgentChildAttributed() async {
        let tracker = AIProcessTracker(lineage: ProcessLineage())
        // The agent→shell lineage Gate-7 needs: an Apple-shipped interpreter
        // (/usr/bin/osascript) running UNDER a real agent. The child subject is
        // Apple-shipped, but it must STILL be attributed via its non-Apple AI
        // ANCESTOR — we must NOT blanket-reject Apple binaries as CHILDREN.
        let ancestors = [
            ancestor(1100, "/bin/zsh"),        // intermediate shell (Apple)
            ancestor(1099, claudePath),        // real Claude Code root (non-Apple)
        ]
        let result = await tracker.isAIChild(pid: 1101, ancestors: ancestors)
        #expect(result.isChild == true, "an Apple interpreter under a real agent root must still be attributed")
        #expect(result.toolType == .claudeCode)
    }

    @Test("A recycled pid present in childToSession but NOT in lineage is re-evaluated, not attributed")
    func recycledPidNotAttributed() async {
        let tracker = AIProcessTracker(lineage: ProcessLineage())
        // Register a genuine child of an AI root → populates childToSession.
        let aiAncestor = ancestor(2000, claudePath)
        let first = await tracker.isAIChild(pid: 2001, ancestors: [aiAncestor])
        #expect(first.isChild == true)
        // Now pid 2001 is RECYCLED by an unrelated process (XProtect) whose
        // ancestry does NOT contain the AI root 2000. Pre-fix this returned the
        // stale Claude Code attribution from the direct-map lookup. Post-fix the
        // cache is only honored when the AI root is still in the ancestry, so
        // this is re-evaluated and (no AI ancestor) returns not-a-child.
        let unrelatedAncestors = [
            ancestor(2050, "/usr/libexec/xpcproxy"),
            ancestor(2049, "/sbin/launchd"),
        ]
        let recycled = await tracker.isAIChild(pid: 2001, ancestors: unrelatedAncestors)
        #expect(recycled.isChild == false, "a recycled pid not descending from the AI root must not inherit attribution")
    }

    @Test("processExited evicts the child→session mapping")
    func processExitedEvicts() async {
        let tracker = AIProcessTracker(lineage: ProcessLineage())
        let aiAncestor = ancestor(3000, claudePath)
        _ = await tracker.isAIChild(pid: 3001, ancestors: [aiAncestor])
        // Child exits.
        await tracker.processExited(pid: 3001)
        // A new process recycles pid 3001 with NO AI ancestry — even the direct
        // cache path is gone now, so it's cleanly not-a-child.
        let recycled = await tracker.isAIChild(
            pid: 3001, ancestors: [ancestor(3050, "/usr/libexec/xpcproxy")])
        #expect(recycled.isChild == false)
    }

    @Test("processExited on the AI root tears down the session")
    func processExitedRootTeardown() async {
        let tracker = AIProcessTracker(lineage: ProcessLineage())
        await tracker.registerAIProcess(pid: 4000, type: .claudeCode, projectDir: "/proj")
        #expect(await tracker.sessionCount == 1)
        await tracker.processExited(pid: 4000)
        #expect(await tracker.sessionCount == 0)
    }
}
