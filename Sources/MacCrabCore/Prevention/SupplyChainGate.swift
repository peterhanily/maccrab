import Foundation
import os.log

/// Blocks installation of suspiciously fresh packages by killing the
/// installer process when the package freshness check returns critical risk.
public actor SupplyChainGate {
    private let logger = Logger(subsystem: "com.maccrab.prevention", category: "supply-chain-gate")

    public struct BlockedInstall: Sendable {
        public let packageName: String
        public let registry: String
        public let ageHours: Double?
        public let installerPid: Int32
        public let reason: String
        public let timestamp: Date
    }

    private var isEnabled = false
    private var blockedInstalls: [BlockedInstall] = []
    private let maxAgeHours: Double  // Block packages younger than this

    public init(maxAgeHours: Double = 24) {
        self.maxAgeHours = maxAgeHours
    }

    /// Enable the supply chain gate.
    public func enable() {
        isEnabled = true
        logger.info("Supply chain gate enabled: blocking packages < \(self.maxAgeHours)h old")
    }

    /// Disable the gate.
    public func disable() {
        isEnabled = false
        logger.info("Supply chain gate disabled")
    }

    /// Check a package and kill the installer if it's too fresh.
    /// Returns a BlockedInstall if the package was blocked, nil otherwise.
    public func gate(
        packageName: String,
        registry: String,
        ageInDays: Double?,
        riskLevel: String,
        installerPid: Int32
    ) -> BlockedInstall? {
        guard isEnabled else { return nil }

        // Block if critical risk or if age is under threshold
        let shouldBlock: Bool
        let reason: String

        if riskLevel == "critical" {
            shouldBlock = true
            reason = "Critical risk package — unknown, not found, or extremely fresh"
        } else if let age = ageInDays, age * 24 < maxAgeHours {
            shouldBlock = true
            reason = "Package published \(String(format: "%.1f", age * 24)) hours ago (threshold: \(maxAgeHours)h)"
        } else {
            shouldBlock = false
            reason = ""
        }

        guard shouldBlock else { return nil }

        // Kill the installer process
        kill(installerPid, SIGTERM)
        logger.warning("Blocked package install: \(packageName) from \(registry). \(reason). Killed PID \(installerPid)")

        // After 2 seconds, SIGKILL if still running
        DispatchQueue.global().asyncAfter(deadline: .now() + 2) {
            kill(installerPid, SIGKILL)
        }

        let blocked = BlockedInstall(
            packageName: packageName,
            registry: registry,
            ageHours: ageInDays.map { $0 * 24 },
            installerPid: installerPid,
            reason: reason,
            timestamp: Date()
        )
        blockedInstalls.append(blocked)

        return blocked
    }

    /// Get history of blocked installs.
    public func history() -> [BlockedInstall] { blockedInstalls }

    public func stats() -> (enabled: Bool, blocked: Int) {
        (isEnabled, blockedInstalls.count)
    }
}
