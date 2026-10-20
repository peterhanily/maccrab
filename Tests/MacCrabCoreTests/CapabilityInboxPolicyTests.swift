// CapabilityInboxPolicyTests.swift
// MacCrabCoreTests
//
// The set-agent-capabilities verb arrives through a mode-1777 inbox. File-owner
// authorization proves only which uid wrote the request, not that a human used
// the dashboard. Pin the interim fail-closed policy until an authenticated
// user-presence channel exists.

import Foundation
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

    @Test("a root request through the root-only channel can create a grant")
    func rootCanGrant() {
        let decision = DaemonTimers.evaluateAgentCapabilityRequest(
            fileOwnerUID: 0,
            payload: ["config": true, "authoring": false, "response": true],
            previousGrants: allOff,
            rootChannel: true
        )

        #expect(decision == .apply(
            grants: ["config": true, "authoring": false, "response": true],
            newlyGranted: ["config", "response"]
        ))
    }

    @Test("a root-owned file in the 1777 inbox cannot grant: it may be a linked copy of an old grant file")
    func rootOwnedPublicInboxCannotGrant() {
        let decision = DaemonTimers.evaluateAgentCapabilityRequest(
            fileOwnerUID: 0,
            payload: ["config": true, "authoring": false, "response": false],
            previousGrants: allOff
        )
        #expect(decision == .rejectNonRootGrant(attempted: ["config"]))
        let revoke = DaemonTimers.evaluateAgentCapabilityRequest(
            fileOwnerUID: 0,
            payload: ["config": false, "authoring": false, "response": false],
            previousGrants: ["config": true, "authoring": false, "response": false]
        )
        #expect(revoke == .apply(grants: allOff, newlyGranted: []), "revokes still work")
        let nonRootChannel = DaemonTimers.evaluateAgentCapabilityRequest(
            fileOwnerUID: 501,
            payload: ["config": true, "authoring": false, "response": false],
            previousGrants: allOff,
            rootChannel: true
        )
        #expect(nonRootChannel == .rejectNonRootGrant(attempted: ["config"]))
    }

    @Test("the root-only directory is created 0700 and a non-directory is refused")
    func rootInboxDirectory() throws {
        let base = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrab-root-inbox-\(UUID().uuidString)").path
        try FileManager.default.createDirectory(atPath: base, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: base) }
        let dir = base + "/inbox-root"
        #expect(DaemonTimers.ensureRootInboxDirectory(at: dir))
        let mode = try FileManager.default.attributesOfItem(atPath: dir)[.posixPermissions] as? Int
        #expect(mode == 0o700)
        chmod(dir, 0o777)
        #expect(DaemonTimers.ensureRootInboxDirectory(at: dir), "a widened mode is narrowed again")
        let narrowed = try FileManager.default.attributesOfItem(atPath: dir)[.posixPermissions] as? Int
        #expect(narrowed == 0o700)
        let link = base + "/linked"
        try FileManager.default.createSymbolicLink(atPath: link, withDestinationPath: dir)
        #expect(!DaemonTimers.ensureRootInboxDirectory(at: link), "a symlink is refused")
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
