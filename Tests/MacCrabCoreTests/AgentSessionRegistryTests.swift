// AgentSessionRegistryTests.swift
//
// The load-bearing proof for the Wave-3 session recorder Phase-1 spike.
// The whole design hinges on one claim: a durable session id can be
// minted once at the AI-tool root and resolved for EVERY correlated
// event — the AI tool's own events AND its descendants, including
// descendants that outlive the root. If any of these resolve to nil,
// the durable store would just persist gaps.
//
// EventLoop calls session(...) in the AI-tool ROOT branch and
// sessionForRoot(...) in the descendant branch (after walking ancestry
// to the nearest AI-tool pid). These tests exercise that exact contract
// with injected time — no sleeps, fully deterministic.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("AgentSessionRegistry — durable session-id coverage")
struct AgentSessionRegistryTests {

    private let T0 = Date(timeIntervalSince1970: 1_700_000_000)
    private let rootPid: Int32 = 1000
    private let hClaude = ProcessIdentity.fnv1a64("/Users/x/.local/bin/claude")

    /// Mint a root session, then assert all four critic coverage cases
    /// resolve to the SAME non-empty id.
    @Test("(a) direct child, (b) deep descendant, (c) root's own event all share one id")
    func allRailsShareOneSessionId() async {
        let reg = AgentSessionRegistry()

        // (c) the AI tool's OWN event (the root branch) — mints the id.
        let sid = await reg.session(rootPid: rootPid, pathHash: hClaude,
                                    startTime: T0, tool: "claude_code", now: T0)
        #expect(!sid.isEmpty)

        // (a) a direct child: EventLoop walks ancestry → nearest AI-tool
        // pid is the root → sessionForRoot(rootPid).
        let childSid = await reg.sessionForRoot(pid: rootPid, pathHash: hClaude, now: T0.addingTimeInterval(1))
        #expect(childSid == sid)

        // (b) a 3-deep descendant: same resolution — the ancestor walk
        // still lands on rootPid.
        let deepSid = await reg.sessionForRoot(pid: rootPid, pathHash: hClaude, now: T0.addingTimeInterval(2))
        #expect(deepSid == sid)

        // Calling the root branch again for the same identity is idempotent.
        let sid2 = await reg.session(rootPid: rootPid, pathHash: hClaude,
                                     startTime: T0, tool: "claude_code", now: T0.addingTimeInterval(3))
        #expect(sid2 == sid)
    }

    /// (d) THE crux: a descendant event arriving AFTER the root process
    /// has exited must still resolve (children routinely outlive parents).
    /// Within the grace window → resolves; well past it → drops.
    @Test("(d) descendant after root exit resolves within grace, drops past it")
    func descendantAfterRootExit() async {
        let reg = AgentSessionRegistry(graceWindow: 300)
        let sid = await reg.session(rootPid: rootPid, pathHash: hClaude,
                                    startTime: T0, tool: "claude_code", now: T0)

        // Root exits at T0+10.
        await reg.end(rootPid: rootPid, now: T0.addingTimeInterval(10))

        // A descendant event at T0+20 (10s after exit, inside grace) still
        // correlates — the durable id outlives the process.
        let inGrace = await reg.sessionForRoot(pid: rootPid, pathHash: hClaude, now: T0.addingTimeInterval(20))
        #expect(inGrace == sid)

        // Far past grace (T0+10+301), the session is no longer resolvable.
        let pastGrace = await reg.sessionForRoot(pid: rootPid, pathHash: hClaude, now: T0.addingTimeInterval(311))
        #expect(pastGrace == nil)
    }

    /// PID recycle safety: a reused PID running a DIFFERENT executable
    /// must mint a fresh session, and an old-exe descendant lookup must
    /// NOT leak the new session (pathHash guard).
    @Test("recycled PID mints a fresh session and doesn't leak across executables")
    func recycleSafety() async {
        let reg = AgentSessionRegistry()
        let sid1 = await reg.session(rootPid: rootPid, pathHash: hClaude,
                                     startTime: T0, tool: "claude_code", now: T0)

        // Same PID, different executable + later startTime = a recycled PID.
        let hCursor = ProcessIdentity.fnv1a64("/Applications/Cursor.app/Contents/MacOS/cursor")
        let sid2 = await reg.session(rootPid: rootPid, pathHash: hCursor,
                                     startTime: T0.addingTimeInterval(1000), tool: "cursor",
                                     now: T0.addingTimeInterval(1000))
        #expect(sid2 != sid1)

        // A descendant carrying the ORIGINAL exe's pathHash must not match
        // the recycled session.
        let leak = await reg.sessionForRoot(pid: rootPid, pathHash: hClaude, now: T0.addingTimeInterval(1001))
        #expect(leak == nil)

        // A descendant of the new process resolves to the new session.
        let ok = await reg.sessionForRoot(pid: rootPid, pathHash: hCursor, now: T0.addingTimeInterval(1002))
        #expect(ok == sid2)
    }

    /// Two distinct AI-tool roots get distinct ids.
    @Test("distinct roots get distinct session ids")
    func distinctRoots() async {
        let reg = AgentSessionRegistry()
        let a = await reg.session(rootPid: 1000, pathHash: hClaude, startTime: T0, tool: "claude_code", now: T0)
        let b = await reg.session(rootPid: 2000, pathHash: hClaude, startTime: T0, tool: "claude_code", now: T0)
        #expect(a != b)
    }
}
