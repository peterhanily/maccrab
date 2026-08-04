// SystemExtensionManager.swift
//
// Drives the OSSystemExtensionRequest lifecycle for the MacCrab
// Endpoint Security extension. Activated on first launch; the delegate
// callbacks below handle the approval prompt, replace-on-upgrade, and
// success/failure UI updates.
//
// Why this file exists at all: starting with macOS Catalina, Apple's
// AMFI refuses com.apple.developer.endpoint-security.client on any
// binary that isn't loaded by sysextd via OSSystemExtensionRequest.
// LaunchDaemons with the entitlement get SIGKILLed (Error -413). See
// v1.3.0 CHANGELOG for the full diagnosis.

import Foundation
import SystemExtensions
import os.log

public enum SystemExtensionState: Equatable, Sendable {
    case unknown            // We haven't checked yet
    case notActivated       // Extension isn't registered
    case activating         // Waiting for sysextd to respond
    case awaitingApproval   // System Settings prompt is showing
    case activated          // Running
    case failed(String)     // Activation error
}

/// What the most recent submitted request is trying to achieve. Set
/// when `activate()` / `deactivate()` submits the request; consumed in
/// the delegate result handler so a successful deactivation doesn't
/// flip the badge back to "Active" (the v1.9.0 audit-fix; pre-fix
/// every `.completed` result was treated as activation).
public enum SystemExtensionIntent: Equatable, Sendable {
    case activate
    case deactivate
}

@MainActor
public final class SystemExtensionManager: NSObject, ObservableObject {

    public static let extensionIdentifier = "com.maccrab.agent"
    static let removalPendingPreference = "systemExtensionRemovalPending"
    private let logger = Logger(subsystem: "com.maccrab.app", category: "sysext-manager")

    @Published public private(set) var state: SystemExtensionState = .unknown
    @Published public private(set) var statusMessage: String = ""

    /// Intent of the in-flight request. Reset to nil after the result
    /// handler runs. Internal-visibility so tests can drive the state
    /// machine without going through the OS framework.
    private(set) var pendingIntent: SystemExtensionIntent?

    /// Explicit removal outranks the app's automatic cold-start activation.
    /// OSSystemExtensionManager does not offer cancellation, so a removal that
    /// arrives while activation is in flight is submitted immediately after
    /// that request settles.  A Bool deliberately coalesces repeated deep-link
    /// and button clicks into one OS request.
    private(set) var deactivationQueued = false

    /// Test seam for proving request ordering without asking sysextd to mutate
    /// the running host. Production uses OSSystemExtensionManager directly.
    private let requestSubmitter: ((OSSystemExtensionRequest) -> Void)?
    private let preferences: UserDefaults

    var removalPending: Bool {
        preferences.bool(forKey: Self.removalPendingPreference)
    }

    /// Automatic recovery must stand down while an explicit removal is queued
    /// or in flight, but that process-local intent is not durable proof that
    /// macOS accepted the removal. The persisted latch is set only from a
    /// successful deactivation result below.
    var automaticActivationSuppressed: Bool {
        removalPending || deactivationQueued || pendingIntent == .deactivate
    }

    /// True when protection is off AND the watchdog is structurally unable to
    /// restore it, so only a human click will. Distinct from a transient
    /// in-flight removal, which resolves on its own — the UI must be able to
    /// tell "wait a moment" apart from "nothing will happen until you act".
    @Published public private(set) var needsExplicitReactivation = false

    /// The latched-off condition is re-evaluated on every watchdog tick (every
    /// few minutes, indefinitely). Report it loudly once per occurrence rather
    /// than emitting a fault on every tick.
    private var hasReportedLatchedActivation = false

    public override init() {
        requestSubmitter = nil
        preferences = .standard
        super.init()
    }

    init(
        preferences: UserDefaults,
        requestSubmitter: @escaping (OSSystemExtensionRequest) -> Void
    ) {
        self.requestSubmitter = requestSubmitter
        self.preferences = preferences
        super.init()
    }

    /// Reserve the single request slot before constructing an OS request.
    /// Window appearance, first-run setup and the heartbeat watchdog can all
    /// converge during startup; submitting each one produced duplicate system
    /// authorization UI. MainActor serialization makes this a process-local
    /// in-flight gate without changing the semantics of a later explicit
    /// reactivation after the current request settles.
    @discardableResult
    func beginRequest(intent: SystemExtensionIntent) -> Bool {
        guard pendingIntent == nil else { return false }
        pendingIntent = intent
        state = .activating
        switch intent {
        case .activate:
            statusMessage = "Requesting extension activation…"
        case .deactivate:
            statusMessage = "Deactivating extension…"
        }
        return true
    }

    /// Explicit user activation (Welcome/Enable/Repair). This is the only path
    /// that clears a persisted removal latch, and only after it successfully
    /// reserves the request slot. A click received while deactivation is in
    /// flight must not erase an accepted machine-removal choice without
    /// actually submitting the requested reversal.
    public func activate() {
        submitActivation(explicit: true)
    }

    /// Automatic cold-launch/watchdog activation. An accepted removal —
    /// including one waiting for reboot — persists an opt-out so relaunch or a
    /// stale heartbeat cannot silently undo the operator's explicit intent.
    /// A merely queued/in-flight removal suppresses only this process.
    public func activateAutomatically() {
        guard !automaticActivationSuppressed else {
            if removalPending {
                // DURABLE refusal: only an explicit Enable/Repair click clears
                // this latch, so the engine is down and will stay down until a
                // human acts. This used to be indistinguishable from the
                // transient case below — one `notice`, no state change — and on
                // one host the app ran for nine hours logging it every five
                // minutes while the Mac had NO protection at all and the
                // operator believed a qualification run was under way. Refusing
                // is correct; refusing quietly is not.
                needsExplicitReactivation = true
                state = .notActivated
                statusMessage = "Protection is OFF — automatic restart is paused because "
                    + "extension removal was accepted earlier. Click Enable Protection to restore it."
                if !hasReportedLatchedActivation {
                    hasReportedLatchedActivation = true
                    logger.fault("""
                        Protection is OFF and cannot self-heal: automatic activation is latched off \
                        by a previously accepted extension removal. An explicit Enable/Repair is required.
                        """)
                }
            } else {
                // TRANSIENT: a removal is queued or in flight. It settles on its
                // own, so this genuinely is a routine skip.
                logger.notice("Skipping automatic activation while an extension removal request is in flight")
                statusMessage = "Automatic activation paused while the removal request settles."
            }
            return
        }
        submitActivation(explicit: false)
    }

    private func submitActivation(explicit: Bool) {
        guard beginRequest(intent: .activate) else {
            logger.info("Skipping duplicate activation request while another system-extension request is in flight")
            return
        }
        if explicit {
            preferences.set(false, forKey: Self.removalPendingPreference)
            deactivationQueued = false
        }
        // An activation is now actually in flight, so the "only you can fix
        // this" condition no longer holds — and if it recurs later it should be
        // reported again rather than swallowed by the once-only guard.
        needsExplicitReactivation = false
        hasReportedLatchedActivation = false
        logger.info("Submitting activation request for \(Self.extensionIdentifier, privacy: .public)")

        let request = OSSystemExtensionRequest.activationRequest(
            forExtensionWithIdentifier: Self.extensionIdentifier,
            queue: .main
        )
        request.delegate = self
        submit(request)
    }

    /// Trigger a deactivation — the dashboard's "Remove System
    /// Extension" button. macOS shows a system-modal approval dialog;
    /// the result handler maps `.completed` to `.notActivated` so the
    /// status pill doesn't lie.
    public func deactivate() {
        if pendingIntent == .activate {
            deactivationQueued = true
            statusMessage = "Extension removal queued behind the current activation request…"
            logger.notice("Queueing explicit deactivation behind in-flight activation")
            return
        }
        guard beginRequest(intent: .deactivate) else {
            logger.info("Skipping duplicate deactivation request while another system-extension request is in flight")
            return
        }
        logger.info("Submitting deactivation request")

        let request = OSSystemExtensionRequest.deactivationRequest(
            forExtensionWithIdentifier: Self.extensionIdentifier,
            queue: .main
        )
        request.delegate = self
        submit(request)
    }

    /// Apply a request result against a known intent. Pulled out of
    /// the delegate callback so tests can verify the intent → state
    /// mapping without needing a real OSSystemExtensionRequest.
    /// Visible to the same module so the test target can call it.
    func applyResult(intent: SystemExtensionIntent, result: OSSystemExtensionRequest.Result) {
        switch (intent, result) {
        case (.activate, .completed):
            state = .activated
            statusMessage = "Endpoint Security extension is active."
        case (.deactivate, .completed):
            preferences.set(true, forKey: Self.removalPendingPreference)
            state = .notActivated
            statusMessage = "Endpoint Security extension removed."
        case (.activate, .willCompleteAfterReboot):
            state = .awaitingApproval
            statusMessage = "Extension will finish activating after reboot."
        case (.deactivate, .willCompleteAfterReboot):
            preferences.set(true, forKey: Self.removalPendingPreference)
            state = .awaitingApproval
            statusMessage = "Extension will finish deactivating after reboot."
        @unknown default:
            // Future result cases — follow the intent so the badge at
            // least reflects what the user just clicked, even if the OS
            // returned a status we don't yet model.
            switch intent {
            case .activate:   state = .activated
            case .deactivate: state = .notActivated
            }
            statusMessage = "Operation completed with status \(result.rawValue)."
        }
        pendingIntent = nil
        submitQueuedDeactivation(after: intent)
    }

    /// Apply a request failure against a known intent. Same testable
    /// shape as `applyResult`.
    func applyFailure(intent: SystemExtensionIntent, error: Error) {
        if intent == .deactivate {
            // Cancellation and rejection are both delivered as failures. Do
            // not leave transient queue state suppressing the watchdog after
            // macOS declined this request. A durable latch, if present, came
            // from an earlier accepted removal and must not be undone by a
            // later redundant request failing.
            deactivationQueued = false
        }
        state = .failed(error.localizedDescription)
        let prefix: String
        switch intent {
        case .activate:   prefix = "Activation failed"
        case .deactivate: prefix = "Deactivation failed"
        }
        statusMessage = "\(prefix): \(error.localizedDescription)"
        pendingIntent = nil
        submitQueuedDeactivation(after: intent)
    }

    private func submit(_ request: OSSystemExtensionRequest) {
        if let requestSubmitter {
            requestSubmitter(request)
        } else {
            OSSystemExtensionManager.shared.submitRequest(request)
        }
    }

    private func submitQueuedDeactivation(after settledIntent: SystemExtensionIntent) {
        guard settledIntent == .activate, deactivationQueued else { return }
        deactivationQueued = false
        // `pendingIntent` was cleared by the result/failure handler above, so
        // this reserves the one request slot and submits exactly once.
        deactivate()
    }
}

// MARK: - OSSystemExtensionRequestDelegate

extension SystemExtensionManager: OSSystemExtensionRequestDelegate {

    nonisolated public func request(
        _ request: OSSystemExtensionRequest,
        actionForReplacingExtension existing: OSSystemExtensionProperties,
        withExtension ext: OSSystemExtensionProperties
    ) -> OSSystemExtensionRequest.ReplacementAction {
        // Upgrading — always replace so a new app version takes effect.
        // If the user is deliberately running a pinned older version
        // they can revert by re-installing the prior release's DMG.
        logger.info("Replacing installed extension: \(existing.bundleShortVersion, privacy: .public) → \(ext.bundleShortVersion, privacy: .public)")
        return .replace
    }

    nonisolated public func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        logger.info("Request needs user approval")
        Task { @MainActor in
            self.state = .awaitingApproval
            // Tailor the copy to whether we're activating or
            // deactivating so the user sees the right next-step.
            let detail: String
            switch self.pendingIntent {
            case .deactivate:
                detail = "Approve the deactivation in System Settings > General > Login Items & Extensions > Endpoint Security Extensions."
            default:
                detail = "Approve the extension in System Settings > General > Login Items & Extensions > Endpoint Security Extensions."
            }
            self.statusMessage = detail
        }
    }

    nonisolated public func request(
        _ request: OSSystemExtensionRequest,
        didFinishWithResult result: OSSystemExtensionRequest.Result
    ) {
        logger.info("Request finished: \(String(describing: result), privacy: .public)")
        Task { @MainActor in
            // Default to .activate when the intent was somehow lost
            // (shouldn't happen; the intent is set synchronously
            // before submitRequest runs). Backwards-compatible with
            // the pre-v1.9 single-purpose path.
            let intent = self.pendingIntent ?? .activate
            self.applyResult(intent: intent, result: result)
        }
    }

    nonisolated public func request(
        _ request: OSSystemExtensionRequest,
        didFailWithError error: Error
    ) {
        logger.error("Request failed: \(error.localizedDescription, privacy: .public)")
        Task { @MainActor in
            let intent = self.pendingIntent ?? .activate
            self.applyFailure(intent: intent, error: error)
        }
    }
}
