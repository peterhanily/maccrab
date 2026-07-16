import Foundation
import os.log

/// TCC-permission revocation **mechanism** — resets permissions for a specific
/// service + bundle ID via `tccutil reset`.
///
/// STATUS (v1.21.4): ADVISORY / NOT-YET-WIRED. This is the mechanism only. As of
/// this build `shouldRevoke(...)` / `revoke(...)` have **no production caller** —
/// they are exercised by unit tests alone (grep: the only non-test reference is
/// this type being constructed + `enable()`d in `DaemonSetup`). Nothing in any
/// collector or event path invokes them, so **no TCC grant is ever auto-revoked
/// at runtime.** Do not describe this as an active prevention: it is dormant-but-
/// ready. `enable()` merely un-gates the methods for a future caller; it does not
/// itself wire anything.
///
/// WIRING RESIDUAL (owner action, OUT OF THIS FILE'S SCOPE — needs an edit to the
/// TCCMonitor emission path or the EventLoop that consumes its stream, neither of
/// which this type may reach on its own):
///   In `TCCMonitor.emitEvent(...)` on a NEW allowed grant (`eventAction ==
///   "tcc_grant"`), the `service`, `client` (bundleId) and resolved `SignerType`
///   are all already in hand. Give the monitor (or the event loop) the shared
///   `DaemonState.tccRevocation` handle and add the single gated call:
///
///       if await tccRevocation.shouldRevoke(service: entry.service,
///                                            bundleId: entry.client,
///                                            signerType: signerType) {
///           _ = await tccRevocation.revoke(service: entry.service,
///                                          bundleId: entry.client,
///                                          reason: "unsigned app granted \(entry.service)")
///       }
///
///   That call site MUST also apply the RESPONSE_SAFETY TCC service-name allowlist
///   (SafePIDValidator-style) so a revocation can never brick the operator's own /
///   the dashboard's TCC grants — `sensitiveServices` here is a fire-on set, NOT a
///   safe-to-revoke allowlist.
///
/// DOC RECONCILIATION RESIDUAL (owner): the startup banner
/// (`DaemonSetup`/`StartupBanner`) and `docs/RESPONSE_SAFETY.md` currently list
/// "TCC revocation" among ACTIVE preventions. Until the wiring above lands, those
/// over-claim — reword them to "advisory / mechanism-only" or add the wiring.
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
    /// DORMANT: no production caller yet — see the type doc's WIRING RESIDUAL. A
    /// caller MUST gate this behind a service-name allowlist (RESPONSE_SAFETY).
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
    /// DORMANT: no production caller yet — see the type doc's WIRING RESIDUAL.
    /// `true` here means "this grant is in the fire-on set", NOT "safe to revoke";
    /// the caller must still apply the service-name allowlist before `revoke(...)`.
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
