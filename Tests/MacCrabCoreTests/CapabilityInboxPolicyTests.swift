// CapabilityInboxPolicyTests.swift
// MacCrabCoreTests
//
// The set-agent-capabilities verb arrives through a mode-1777 inbox. File-owner
// authorization proves only which uid wrote the request, not that a human used
// the dashboard. Pin the interim fail-closed policy until an authenticated
// user-presence channel exists.

import Testing
@testable import MacCrabAgentKit

@Suite("Capability inbox grant policy")
struct CapabilityInboxPolicyTests {
    private let allOff = [
        "config": false,
        "authoring": false,
        "response": false,
    ]

    @Test("non-root console admin cannot create a grant")
    func nonRootCannotGrant() {
        let decision = DaemonTimers.evaluateAgentCapabilityRequest(
            fileOwnerUID: 501,
            payload: ["config": true, "authoring": false, "response": false],
            previousGrants: allOff
        )

        #expect(decision == .rejectNonRootGrant(attempted: ["config"]))
    }

    @Test("root-owned request can create a grant")
    func rootCanGrant() {
        let decision = DaemonTimers.evaluateAgentCapabilityRequest(
            fileOwnerUID: 0,
            payload: ["config": true, "authoring": false, "response": true],
            previousGrants: allOff
        )

        #expect(decision == .apply(
            grants: ["config": true, "authoring": false, "response": true],
            newlyGranted: ["config", "response"]
        ))
    }

    @Test("non-root console admin can revoke while retaining an existing grant")
    func nonRootCanRevoke() {
        let previous = ["config": true, "authoring": true, "response": false]
        let decision = DaemonTimers.evaluateAgentCapabilityRequest(
            fileOwnerUID: 501,
            payload: ["config": false, "authoring": true, "response": false],
            previousGrants: previous
        )

        #expect(decision == .apply(
            grants: ["config": false, "authoring": true, "response": false],
            newlyGranted: []
        ))
    }

    @Test("mixed non-root grant and revoke is rejected atomically")
    func mixedRequestRejectedUnchanged() {
        let previous = ["config": true, "authoring": false, "response": false]
        let decision = DaemonTimers.evaluateAgentCapabilityRequest(
            fileOwnerUID: 501,
            payload: ["config": false, "authoring": true, "response": false],
            previousGrants: previous
        )

        var persisted = previous
        if case let .apply(grants, _) = decision {
            persisted = grants
        }
        #expect(decision == .rejectNonRootGrant(attempted: ["authoring"]))
        #expect(persisted == previous)
    }

    @Test("payload requester claims cannot spoof root ownership")
    func spoofedRequesterIsIrrelevant() {
        let decision = DaemonTimers.evaluateAgentCapabilityRequest(
            fileOwnerUID: 501,
            payload: [
                "config": true,
                "authoring": false,
                "response": false,
                "requester": "root",
                "requester_uid": 0,
                "uid": 0,
            ],
            previousGrants: allOff
        )

        #expect(decision == .rejectNonRootGrant(attempted: ["config"]))
    }
}
