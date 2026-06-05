// SystemExtensionManagerTests.swift
// MacCrabAppTests
//
// Drives the OSSystemExtensionRequest result/failure state machine through
// its internal test seam (applyResult/applyFailure). The v1.9.0 audit fix
// lives here: a successful DEACTIVATION must not flip the badge back to
// "Active" — pre-fix every .completed result was treated as activation.

import Testing
import Foundation
import SystemExtensions
@testable import MacCrabApp

@MainActor
@Suite("SystemExtensionManager state machine")
struct SystemExtensionManagerTests {

    @Test("Activate + completed → activated")
    func activateCompleted() {
        let m = SystemExtensionManager()
        m.applyResult(intent: .activate, result: .completed)
        #expect(m.state == .activated)
        #expect(m.statusMessage == "Endpoint Security extension is active.")
        #expect(m.pendingIntent == nil)
    }

    @Test("Deactivate + completed → notActivated (badge must not lie)")
    func deactivateCompleted() {
        let m = SystemExtensionManager()
        m.applyResult(intent: .deactivate, result: .completed)
        #expect(m.state == .notActivated)
        #expect(m.statusMessage == "Endpoint Security extension removed.")
        #expect(m.pendingIntent == nil)
    }

    @Test("willCompleteAfterReboot → awaitingApproval for both intents")
    func rebootPending() {
        let a = SystemExtensionManager()
        a.applyResult(intent: .activate, result: .willCompleteAfterReboot)
        #expect(a.state == .awaitingApproval)
        #expect(a.statusMessage.contains("reboot"))

        let d = SystemExtensionManager()
        d.applyResult(intent: .deactivate, result: .willCompleteAfterReboot)
        #expect(d.state == .awaitingApproval)
        #expect(d.statusMessage.contains("reboot"))
    }

    @Test("Failure carries the intent-specific prefix and error text")
    func failures() {
        let err = NSError(domain: "test", code: 1,
                          userInfo: [NSLocalizedDescriptionKey: "boom"])

        let a = SystemExtensionManager()
        a.applyFailure(intent: .activate, error: err)
        #expect(a.state == .failed("boom"))
        #expect(a.statusMessage == "Activation failed: boom")
        #expect(a.pendingIntent == nil)

        let d = SystemExtensionManager()
        d.applyFailure(intent: .deactivate, error: err)
        #expect(d.state == .failed("boom"))
        #expect(d.statusMessage == "Deactivation failed: boom")
    }
}
