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
public enum SystemExtensionIntent: Sendable {
    case activate
    case deactivate
}

@MainActor
public final class SystemExtensionManager: NSObject, ObservableObject {

    public static let extensionIdentifier = "com.maccrab.agent"
    private let logger = Logger(subsystem: "com.maccrab.app", category: "sysext-manager")

    @Published public private(set) var state: SystemExtensionState = .unknown
    @Published public private(set) var statusMessage: String = ""

    /// Intent of the in-flight request. Reset to nil after the result
    /// handler runs. Internal-visibility so tests can drive the state
    /// machine without going through the OS framework.
    private(set) var pendingIntent: SystemExtensionIntent?

    public override init() {
        super.init()
    }

    /// Kick off activation. Safe to call multiple times — sysextd
    /// dedups and either returns an already-active extension or replaces
    /// an older build with the currently-bundled one.
    public func activate() {
        logger.info("Submitting activation request for \(Self.extensionIdentifier, privacy: .public)")
        pendingIntent = .activate
        state = .activating
        statusMessage = "Requesting extension activation…"

        let request = OSSystemExtensionRequest.activationRequest(
            forExtensionWithIdentifier: Self.extensionIdentifier,
            queue: .main
        )
        request.delegate = self
        OSSystemExtensionManager.shared.submitRequest(request)
    }

    /// Trigger a deactivation — the dashboard's "Remove System
    /// Extension" button. macOS shows a system-modal approval dialog;
    /// the result handler maps `.completed` to `.notActivated` so the
    /// status pill doesn't lie.
    public func deactivate() {
        logger.info("Submitting deactivation request")
        pendingIntent = .deactivate
        state = .activating
        statusMessage = "Deactivating extension…"

        let request = OSSystemExtensionRequest.deactivationRequest(
            forExtensionWithIdentifier: Self.extensionIdentifier,
            queue: .main
        )
        request.delegate = self
        OSSystemExtensionManager.shared.submitRequest(request)
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
            state = .notActivated
            statusMessage = "Endpoint Security extension removed."
        case (.activate, .willCompleteAfterReboot):
            state = .awaitingApproval
            statusMessage = "Extension will finish activating after reboot."
        case (.deactivate, .willCompleteAfterReboot):
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
    }

    /// Apply a request failure against a known intent. Same testable
    /// shape as `applyResult`.
    func applyFailure(intent: SystemExtensionIntent, error: Error) {
        state = .failed(error.localizedDescription)
        let prefix: String
        switch intent {
        case .activate:   prefix = "Activation failed"
        case .deactivate: prefix = "Deactivation failed"
        }
        statusMessage = "\(prefix): \(error.localizedDescription)"
        pendingIntent = nil
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
