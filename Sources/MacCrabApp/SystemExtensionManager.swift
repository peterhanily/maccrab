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

@MainActor
public final class SystemExtensionManager: NSObject, ObservableObject {

    public static let extensionIdentifier = "com.maccrab.agent"
    private let logger = Logger(subsystem: "com.maccrab.app", category: "sysext-manager")

    @Published public private(set) var state: SystemExtensionState = .unknown
    @Published public private(set) var statusMessage: String = ""

    public override init() {
        super.init()
    }

    /// Kick off activation. Safe to call multiple times — sysextd
    /// dedups and either returns an already-active extension or replaces
    /// an older build with the currently-bundled one.
    public func activate() {
        logger.info("Submitting activation request for \(Self.extensionIdentifier, privacy: .public)")
        state = .activating
        statusMessage = "Requesting extension activation…"

        let request = OSSystemExtensionRequest.activationRequest(
            forExtensionWithIdentifier: Self.extensionIdentifier,
            queue: .main
        )
        request.delegate = self
        OSSystemExtensionManager.shared.submitRequest(request)
    }

    /// Trigger a deactivation — only useful during development or an
    /// explicit uninstall flow. The uninstaller also calls
    /// `systemextensionsctl uninstall <team> com.maccrab.agent`.
    public func deactivate() {
        logger.info("Submitting deactivation request")
        state = .activating
        statusMessage = "Deactivating extension…"

        let request = OSSystemExtensionRequest.deactivationRequest(
            forExtensionWithIdentifier: Self.extensionIdentifier,
            queue: .main
        )
        request.delegate = self
        OSSystemExtensionManager.shared.submitRequest(request)
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
        logger.info("Activation needs user approval")
        Task { @MainActor in
            self.state = .awaitingApproval
            self.statusMessage = "Approve the extension in System Settings > General > Login Items & Extensions > Endpoint Security Extensions."
        }
    }

    nonisolated public func request(
        _ request: OSSystemExtensionRequest,
        didFinishWithResult result: OSSystemExtensionRequest.Result
    ) {
        logger.info("Activation finished: \(String(describing: result), privacy: .public)")
        Task { @MainActor in
            switch result {
            case .completed:
                self.state = .activated
                self.statusMessage = "Endpoint Security extension is active."
            case .willCompleteAfterReboot:
                self.state = .awaitingApproval
                self.statusMessage = "Extension will finish activating after reboot."
            @unknown default:
                self.state = .activated
                self.statusMessage = "Activation completed with status \(result.rawValue)."
            }
        }
    }

    nonisolated public func request(
        _ request: OSSystemExtensionRequest,
        didFailWithError error: Error
    ) {
        logger.error("Activation failed: \(error.localizedDescription, privacy: .public)")
        Task { @MainActor in
            self.state = .failed(error.localizedDescription)
            self.statusMessage = "Activation failed: \(error.localizedDescription)"
        }
    }
}
