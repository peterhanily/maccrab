// SourceRestartPolicyTests.swift
// v1.18 — the collector restart/escalation logic that replaced the silent
// fixed-2s re-iterate-forever spin in DaemonState.mergedEventStream.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("SourceRestartPolicy: backoff + down escalation (v1.18)")
struct SourceRestartPolicyTests {

    @Test("backoff is exponential and capped; a productive attach stays at base")
    func backoff() {
        let p = SourceRestartPolicy(baseDelay: 2, maxDelay: 60, downThreshold: 5)
        #expect(p.delay(consecutiveEmpty: 0) == 2)   // produced → base
        #expect(p.delay(consecutiveEmpty: 1) == 2)   // 2 * 2^0
        #expect(p.delay(consecutiveEmpty: 2) == 4)   // 2 * 2^1
        #expect(p.delay(consecutiveEmpty: 3) == 8)
        #expect(p.delay(consecutiveEmpty: 4) == 16)
        #expect(p.delay(consecutiveEmpty: 100) == 60) // capped — never hot-spins forever
    }

    @Test("isDown trips at the threshold, not before")
    func downThreshold() {
        let p = SourceRestartPolicy(downThreshold: 5)
        #expect(!p.isDown(consecutiveEmpty: 4))
        #expect(p.isDown(consecutiveEmpty: 5))
        #expect(p.isDown(consecutiveEmpty: 9))
    }

    @Test("a permanently-dead source escalates EXACTLY once, then keeps retrying capped")
    func escalatesOnce() {
        var s = SourceRestartState(policy: SourceRestartPolicy(baseDelay: 2, maxDelay: 60, downThreshold: 3))
        // 2 empty re-attaches below threshold → retry
        if case .retry = s.record(produced: false) {} else { Issue.record("attach 1 should retry") }
        if case .retry = s.record(produced: false) {} else { Issue.record("attach 2 should retry") }
        // 3rd empty → escalate (down)
        if case .escalate = s.record(produced: false) {} else { Issue.record("attach 3 should escalate") }
        // further empties → retry, NOT escalate again (one-shot)
        if case .retry = s.record(produced: false) {} else { Issue.record("attach 4 should retry, not re-escalate") }
        #expect(s.escalated == true)
    }

    @Test("a recovered source resets and reports recovery")
    func recovers() {
        var s = SourceRestartState(policy: SourceRestartPolicy(downThreshold: 2))
        _ = s.record(produced: false)
        _ = s.record(produced: false)          // escalated now
        #expect(s.escalated == true)
        if case .recovered = s.record(produced: true) {} else { Issue.record("a produce after escalation should report recovered") }
        #expect(s.escalated == false)
        #expect(s.consecutiveEmpty == 0)
        // back to normal: a produce that wasn't preceded by escalation is a plain retry
        if case .retry = s.record(produced: true) {} else { Issue.record("normal produce should retry") }
    }
}
