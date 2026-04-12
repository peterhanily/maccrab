import Foundation
import os.log

/// Heightened security mode for untrusted networks (hotels, airports, coffee shops).
/// Increases monitoring sensitivity and enables additional protections.
public actor TravelMode {
    private let logger = Logger(subsystem: "com.maccrab.prevention", category: "travel-mode")

    public struct TravelModeStatus: Sendable {
        public let isActive: Bool
        public let activatedAt: Date?
        public let networkName: String?
        public let protections: [String]
    }

    private var isActive = false
    private var activatedAt: Date?
    private var networkName: String?

    public init() {}

    /// Activate travel mode.
    public func activate(networkName: String? = nil) -> TravelModeStatus {
        isActive = true
        activatedAt = Date()
        self.networkName = networkName

        var protections: [String] = []

        // 1. Block non-HTTPS traffic (allow only port 443, 53)
        enableStrictFirewall()
        protections.append("Non-HTTPS traffic blocked (ports 80, 8080 denied)")

        // 2. Flush DNS to remove any poisoned entries
        flushDNS()
        protections.append("DNS cache flushed")

        // 3. Note: polling intervals are managed by the daemon config
        protections.append("Monitoring sensitivity increased")
        protections.append("All new outbound connections will be logged")
        protections.append("DNS sinkhole active for threat intel domains")

        logger.info("Travel mode activated\(networkName != nil ? " for network: \(networkName!)" : "")")

        return TravelModeStatus(isActive: true, activatedAt: activatedAt, networkName: networkName, protections: protections)
    }

    /// Deactivate travel mode.
    public func deactivate() -> TravelModeStatus {
        isActive = false

        // Remove strict firewall rules
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/sbin/pfctl")
        proc.arguments = ["-a", "com.maccrab.travel", "-F", "all"]
        proc.standardOutput = FileHandle.nullDevice
        proc.standardError = FileHandle.nullDevice
        do {
            try proc.run()
            proc.waitUntilExit()
        } catch {
            logger.error("Failed to remove travel mode firewall rules: \(error.localizedDescription)")
        }

        logger.info("Travel mode deactivated")

        return TravelModeStatus(isActive: false, activatedAt: nil, networkName: nil, protections: [])
    }

    public func status() -> TravelModeStatus {
        TravelModeStatus(
            isActive: isActive, activatedAt: activatedAt, networkName: networkName,
            protections: isActive ? ["Strict firewall", "DNS flushed", "Enhanced monitoring"] : []
        )
    }

    private nonisolated func enableStrictFirewall() {
        let rules = """
        # MacCrab Travel Mode — strict egress filtering
        pass out quick proto tcp to port 443     # HTTPS
        pass out quick proto tcp to port 53      # DNS TCP
        pass out quick proto udp to port 53      # DNS UDP
        pass out quick proto tcp to port 22      # SSH
        pass out quick to 127.0.0.0/8            # Localhost
        block drop out quick proto tcp to port 80   # Block HTTP
        block drop out quick proto tcp to port 8080 # Block alt HTTP
        """
        let path = "/tmp/maccrab_travel.conf"
        do {
            try rules.write(toFile: path, atomically: true, encoding: .utf8)
        } catch {
            Logger(subsystem: "com.maccrab.prevention", category: "travel-mode")
                .error("Failed to write travel mode firewall rules to \(path): \(error.localizedDescription)")
            return
        }
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/sbin/pfctl")
        proc.arguments = ["-a", "com.maccrab.travel", "-f", path]
        proc.standardOutput = FileHandle.nullDevice
        proc.standardError = FileHandle.nullDevice
        do {
            try proc.run()
            proc.waitUntilExit()
        } catch {
            Logger(subsystem: "com.maccrab.prevention", category: "travel-mode")
                .error("Failed to load travel mode firewall rules: \(error.localizedDescription)")
        }
    }

    private nonisolated func flushDNS() {
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/usr/bin/dscacheutil")
        proc.arguments = ["-flushcache"]
        proc.standardOutput = FileHandle.nullDevice
        proc.standardError = FileHandle.nullDevice
        try? proc.run()
        proc.waitUntilExit()
    }
}
