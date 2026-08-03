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

    private func isolatedPreferences() -> UserDefaults {
        let name = "SystemExtensionManagerTests.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: name)!
        defaults.removePersistentDomain(forName: name)
        return defaults
    }

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
        let preferences = isolatedPreferences()
        let m = SystemExtensionManager(preferences: preferences, requestSubmitter: { _ in })
        m.applyResult(intent: .deactivate, result: .completed)
        #expect(m.state == .notActivated)
        #expect(m.statusMessage == "Endpoint Security extension removed.")
        #expect(m.pendingIntent == nil)
        #expect(m.removalPending)
    }

    @Test("willCompleteAfterReboot → awaitingApproval for both intents")
    func rebootPending() {
        let a = SystemExtensionManager()
        a.applyResult(intent: .activate, result: .willCompleteAfterReboot)
        #expect(a.state == .awaitingApproval)
        #expect(a.statusMessage.contains("reboot"))

        let preferences = isolatedPreferences()
        let d = SystemExtensionManager(preferences: preferences, requestSubmitter: { _ in })
        d.applyResult(intent: .deactivate, result: .willCompleteAfterReboot)
        #expect(d.state == .awaitingApproval)
        #expect(d.statusMessage.contains("reboot"))
        #expect(d.removalPending)
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

        let preferences = isolatedPreferences()
        var recoverySubmissions = 0
        let d = SystemExtensionManager(
            preferences: preferences,
            requestSubmitter: { _ in recoverySubmissions += 1 }
        )
        d.applyFailure(intent: .deactivate, error: err)
        #expect(d.state == .failed("boom"))
        #expect(d.statusMessage == "Deactivation failed: boom")
        #expect(!d.removalPending)
        #expect(!d.automaticActivationSuppressed)

        d.activateAutomatically()
        #expect(recoverySubmissions == 1)
        #expect(d.pendingIntent == .activate)
    }

    @Test("Only one system-extension request may be in flight")
    func inFlightRequestsAreDeduplicated() {
        let manager = SystemExtensionManager()

        #expect(manager.beginRequest(intent: .activate))
        #expect(manager.pendingIntent == .activate)
        #expect(manager.state == .activating)
        #expect(manager.statusMessage == "Requesting extension activation…")

        #expect(!manager.beginRequest(intent: .activate))
        #expect(!manager.beginRequest(intent: .deactivate))
        #expect(manager.pendingIntent == .activate)

        manager.applyResult(intent: .activate, result: .completed)
        #expect(manager.pendingIntent == nil)

        #expect(manager.beginRequest(intent: .deactivate))
        #expect(manager.pendingIntent == .deactivate)
        #expect(manager.statusMessage == "Deactivating extension…")
    }

    @Test("Explicit deactivation queues behind activation and submits once")
    func deactivationQueuesBehindActivation() {
        var submissionCount = 0
        let manager = SystemExtensionManager(
            preferences: isolatedPreferences(),
            requestSubmitter: { _ in submissionCount += 1 }
        )

        manager.activate()
        #expect(submissionCount == 1)
        #expect(manager.pendingIntent == .activate)

        manager.deactivate()
        manager.deactivate()
        #expect(submissionCount == 1)
        #expect(manager.pendingIntent == .activate)
        #expect(manager.deactivationQueued)
        #expect(manager.statusMessage.contains("queued"))

        // A second Enable click cannot silently cancel an already-confirmed
        // queued removal while the request slot is still occupied.
        manager.activate()
        #expect(submissionCount == 1)
        #expect(manager.pendingIntent == .activate)
        #expect(manager.deactivationQueued)

        manager.applyResult(intent: .activate, result: .completed)
        #expect(submissionCount == 2)
        #expect(manager.pendingIntent == .deactivate)
        #expect(!manager.deactivationQueued)
        #expect(manager.statusMessage == "Deactivating extension…")

        // Ordinary activation never queues behind a removal request.
        manager.activate()
        #expect(submissionCount == 2)
        #expect(manager.pendingIntent == .deactivate)

        manager.applyResult(intent: .deactivate, result: .completed)
        #expect(manager.pendingIntent == nil)
        #expect(manager.state == .notActivated)
    }

    @Test("Queued deactivation also submits after activation failure")
    func deactivationQueuesAfterActivationFailure() {
        var submissionCount = 0
        let manager = SystemExtensionManager(
            preferences: isolatedPreferences(),
            requestSubmitter: { _ in submissionCount += 1 }
        )
        let error = NSError(
            domain: "test",
            code: 2,
            userInfo: [NSLocalizedDescriptionKey: "activation rejected"]
        )

        manager.activate()
        manager.deactivate()
        manager.applyFailure(intent: .activate, error: error)

        #expect(submissionCount == 2)
        #expect(manager.pendingIntent == .deactivate)
        #expect(!manager.deactivationQueued)
        #expect(manager.statusMessage == "Deactivating extension…")
    }

    @Test("Removal latch blocks launch/watchdog activation across managers")
    func removalLatchBlocksAutomaticActivation() {
        let preferences = isolatedPreferences()
        var firstManagerSubmissions = 0
        let first = SystemExtensionManager(
            preferences: preferences,
            requestSubmitter: { _ in firstManagerSubmissions += 1 }
        )

        first.deactivate()
        #expect(firstManagerSubmissions == 1)
        #expect(!first.removalPending)
        #expect(first.automaticActivationSuppressed)

        // The watchdog is suppressed in memory while removal is in flight,
        // without converting an unaccepted request into a durable opt-out.
        first.activateAutomatically()
        #expect(firstManagerSubmissions == 1)
        first.applyResult(intent: .deactivate, result: .completed)
        first.activateAutomatically()
        #expect(firstManagerSubmissions == 1)
        #expect(first.statusMessage.contains("paused"))

        var relaunchedSubmissions = 0
        let relaunched = SystemExtensionManager(
            preferences: preferences,
            requestSubmitter: { _ in relaunchedSubmissions += 1 }
        )
        relaunched.activateAutomatically()
        #expect(relaunchedSubmissions == 0)
        #expect(relaunched.removalPending)

        // A deliberate Enable/Repair click is allowed to reverse the choice.
        relaunched.activate()
        #expect(relaunchedSubmissions == 1)
        #expect(!relaunched.removalPending)
        #expect(relaunched.pendingIntent == .activate)
    }

    @Test("Reboot-pending deactivation remains latched against auto activation")
    func rebootPendingRemovalRemainsLatched() {
        let preferences = isolatedPreferences()
        var submissions = 0
        let manager = SystemExtensionManager(
            preferences: preferences,
            requestSubmitter: { _ in submissions += 1 }
        )

        manager.deactivate()
        manager.applyResult(intent: .deactivate, result: .willCompleteAfterReboot)
        manager.activateAutomatically()

        #expect(submissions == 1)
        #expect(manager.removalPending)
        #expect(manager.pendingIntent == nil)
    }

    @Test("Failed deactivation clears transient suppression and permits recovery")
    func failedRemovalRestoresAutomaticRecovery() {
        let preferences = isolatedPreferences()
        var submissions = 0
        let manager = SystemExtensionManager(
            preferences: preferences,
            requestSubmitter: { _ in submissions += 1 }
        )
        let error = NSError(
            domain: "OSSystemExtensionErrorDomain",
            code: 4,
            userInfo: [NSLocalizedDescriptionKey: "User cancelled"]
        )

        manager.deactivate()
        #expect(submissions == 1)
        #expect(manager.pendingIntent == .deactivate)
        #expect(manager.automaticActivationSuppressed)

        manager.applyFailure(intent: .deactivate, error: error)
        #expect(manager.pendingIntent == nil)
        #expect(!manager.deactivationQueued)
        #expect(!manager.removalPending)
        #expect(!manager.automaticActivationSuppressed)

        manager.activateAutomatically()
        #expect(submissions == 2)
        #expect(manager.pendingIntent == .activate)
    }

    @Test("A redundant failed removal does not undo an earlier accepted removal")
    func failedRedundantRemovalPreservesAcceptedLatch() {
        let preferences = isolatedPreferences()
        preferences.set(true, forKey: SystemExtensionManager.removalPendingPreference)
        var submissions = 0
        let manager = SystemExtensionManager(
            preferences: preferences,
            requestSubmitter: { _ in submissions += 1 }
        )
        let error = NSError(
            domain: "OSSystemExtensionErrorDomain",
            code: 4,
            userInfo: [NSLocalizedDescriptionKey: "Already removed"]
        )

        manager.deactivate()
        manager.applyFailure(intent: .deactivate, error: error)

        #expect(submissions == 1)
        #expect(manager.removalPending)
        #expect(manager.automaticActivationSuppressed)
        manager.activateAutomatically()
        #expect(submissions == 1)
    }

    @Test("Explicit activation cannot erase an accepted latch while removal is in flight")
    func blockedExplicitActivationPreservesAcceptedRemoval() {
        let preferences = isolatedPreferences()
        preferences.set(true, forKey: SystemExtensionManager.removalPendingPreference)
        var submissions = 0
        let manager = SystemExtensionManager(
            preferences: preferences,
            requestSubmitter: { _ in submissions += 1 }
        )

        manager.deactivate()
        #expect(manager.pendingIntent == .deactivate)
        #expect(manager.removalPending)
        manager.activate()

        #expect(submissions == 1)
        #expect(manager.pendingIntent == .deactivate)
        #expect(manager.removalPending)
        #expect(manager.automaticActivationSuppressed)
    }

    @Test("Queued removal suppresses watchdog without persisting before acceptance")
    func queuedRemovalUsesTransientSuppression() {
        let preferences = isolatedPreferences()
        var submissions = 0
        let manager = SystemExtensionManager(
            preferences: preferences,
            requestSubmitter: { _ in submissions += 1 }
        )

        manager.activate()
        manager.deactivate()
        #expect(manager.deactivationQueued)
        #expect(!manager.removalPending)
        #expect(manager.automaticActivationSuppressed)

        manager.activateAutomatically()
        #expect(submissions == 1)

        manager.applyResult(intent: .activate, result: .completed)
        #expect(submissions == 2)
        #expect(manager.pendingIntent == .deactivate)
        #expect(!manager.removalPending)

        manager.applyResult(intent: .deactivate, result: .completed)
        #expect(manager.removalPending)
    }
}
