// InboxAuthGateTests.swift
//
// v1.19.1 (audit) regression for the privileged-inbox control-plane gate.
// The inbox dir is 1777 (any local user can drop a request file), so
// isAuthorizedInboxRequest is the sole control over who can suppress alerts,
// install rules, or weaken config. The audit found it accepted ANY foreground
// console user (incl. a standard non-admin user on a shared/managed Mac); the
// fix adds an admin-group requirement. These pin the deterministic branches.

import Testing
import Foundation
@testable import MacCrabAgentKit

@Suite("Inbox authorization gate (v1.19.1)")
struct InboxAuthGateTests {

    @Test("root (uid 0) is always authorized")
    func rootAuthorized() {
        #expect(DaemonTimers.isAuthorizedInboxRequest(uid: 0))
    }

    @Test("a stat-failure / negative uid is rejected")
    func negativeRejected() {
        #expect(!DaemonTimers.isAuthorizedInboxRequest(uid: -1))
    }

    @Test("isAdminUID rejects a known non-admin system account (nobody)")
    func nobodyNotAdmin() {
        // uid 'nobody' (4294967294 / -2) is never in the admin group — pins the
        // core new property that a non-admin is rejected.
        #expect(!DaemonTimers.isAdminUID(uid_t.max - 1))
        // And it does not crash on the current runner's uid (admin or not).
        _ = DaemonTimers.isAdminUID(geteuid())
    }

    @Test("a uid that is neither root nor the admin console user is rejected")
    func nonConsoleRejected() {
        // 999999 is not a real logged-in console uid, so the console-user branch
        // can't match it — and even if it somehow did, it isn't an admin. Either
        // way the gate must reject it (the 1777 inbox must not honor arbitrary
        // uids).
        #expect(!DaemonTimers.isAuthorizedInboxRequest(uid: 999999))
    }
}
