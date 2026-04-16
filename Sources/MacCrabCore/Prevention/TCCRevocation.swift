import Foundation
import os.log

/// Auto-revokes TCC permissions when anomalous grants are detected.
/// Uses `tccutil` to reset permissions for specific services and bundle IDs.
public actor TCCRevocation {

    /// MITRE D3FEND defensive technique this module implements.
    public nonisolated static let d3fend = D3FENDMapping.tccRevocation
    private let logger = Logger(subsystem: "com.maccrab.prevention", category: "tcc-revocation")

    public struct RevocationEvent: Sendable {
        public let service: String
        public let bundleId: String
        public let reason: String
        public let timestamp: Date
        public let success: Bool
    }

    /// Services that should be auto-revoked for unsigned/suspicious apps
    private static let sensitiveServices = [
        "Camera", "Microphone", "ScreenCapture", "Accessibility",
        "SystemPolicyAllFiles", "AddressBook", "Calendar", "Photos",
    ]

    private var isEnabled = false
    private var revocationHistory: [RevocationEvent] = []

    public init() {}

    public func enable() {
        isEnabled = true
        logger.info("TCC auto-revocation enabled")
    }

    public func disable() {
        isEnabled = false
        logger.info("TCC auto-revocation disabled")
    }

    /// Revoke a TCC permission for a specific bundle ID.
    /// Returns true if the revocation succeeded.
    public func revoke(service: String, bundleId: String, reason: String) -> Bool {
        guard isEnabled else { return false }

        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/usr/bin/tccutil")
        proc.arguments = ["reset", service, bundleId]
        proc.standardOutput = FileHandle.nullDevice
        proc.standardError = FileHandle.nullDevice

        do {
            try proc.run()
            proc.waitUntilExit()
        } catch {
            logger.error("Failed to revoke TCC: \(error.localizedDescription)")
            let event = RevocationEvent(service: service, bundleId: bundleId, reason: reason, timestamp: Date(), success: false)
            revocationHistory.append(event)
            return false
        }

        let success = proc.terminationStatus == 0
        let event = RevocationEvent(service: service, bundleId: bundleId, reason: reason, timestamp: Date(), success: success)
        revocationHistory.append(event)

        if success {
            logger.info("Revoked TCC \(service) for \(bundleId): \(reason)")
        } else {
            logger.warning("TCC revocation may have failed for \(service)/\(bundleId)")
        }

        return success
    }

    /// Check if a TCC grant should be auto-revoked based on the granting process.
    public func shouldRevoke(service: String, bundleId: String, signerType: String?) -> Bool {
        guard isEnabled else { return false }

        // Auto-revoke if unsigned app gets sensitive permissions
        if signerType == nil || signerType == "unsigned" || signerType == "adHoc" {
            return Self.sensitiveServices.contains(service)
        }

        return false
    }

    public func history() -> [RevocationEvent] { revocationHistory }

    public func stats() -> (enabled: Bool, revoked: Int) {
        (isEnabled, revocationHistory.count)
    }
}
