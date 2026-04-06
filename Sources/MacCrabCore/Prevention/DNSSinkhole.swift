import Foundation
import os.log

/// Prevents C2 callbacks by sinkholing malicious domains to localhost.
/// Writes entries to /etc/hosts that redirect threat-intel domains to 127.0.0.1.
public actor DNSSinkhole {
    private let logger = Logger(subsystem: "com.maccrab.prevention", category: "dns-sinkhole")

    /// Marker comment in /etc/hosts to identify MacCrab-managed entries
    private static let marker = "# MacCrab DNS Sinkhole — DO NOT EDIT BELOW THIS LINE"
    private static let endMarker = "# MacCrab DNS Sinkhole — END"
    private let hostsPath = "/etc/hosts"

    private var sinkholdDomains: Set<String> = []
    private var isEnabled: Bool = false

    public init() {}

    /// Enable the sinkhole with initial domains from threat intel.
    public func enable(domains: Set<String>) {
        sinkholdDomains = domains
        isEnabled = true
        writeHostsFile()
        logger.info("DNS sinkhole enabled: \(domains.count) domains redirected to 127.0.0.1")
    }

    /// Add domains to the sinkhole.
    public func addDomains(_ domains: Set<String>) {
        let newDomains = domains.subtracting(sinkholdDomains)
        guard !newDomains.isEmpty else { return }
        sinkholdDomains.formUnion(newDomains)
        if isEnabled { writeHostsFile() }
        logger.info("Added \(newDomains.count) domains to sinkhole (total: \(self.sinkholdDomains.count))")
    }

    /// Remove all MacCrab entries from /etc/hosts.
    public func disable() {
        isEnabled = false
        sinkholdDomains.removeAll()
        removeHostsEntries()
        logger.info("DNS sinkhole disabled — /etc/hosts cleaned")
    }

    /// Get current sinkhole stats.
    public func stats() -> (enabled: Bool, domainCount: Int) {
        (isEnabled, sinkholdDomains.count)
    }

    private func writeHostsFile() {
        let fm = FileManager.default
        guard fm.isWritableFile(atPath: hostsPath) else {
            logger.warning("Cannot write to /etc/hosts (need root)")
            return
        }

        // Read existing hosts file
        guard var content = try? String(contentsOfFile: hostsPath, encoding: .utf8) else { return }

        // Remove any existing MacCrab section
        if let startRange = content.range(of: Self.marker),
           let endRange = content.range(of: Self.endMarker) {
            content.removeSubrange(startRange.lowerBound..<content.index(after: endRange.upperBound))
        }

        // Append new sinkhole entries
        var section = "\n\(Self.marker)\n"
        for domain in sinkholdDomains.sorted().prefix(10000) {  // Cap at 10K domains
            section += "127.0.0.1 \(domain)\n"
            section += "::1 \(domain)\n"
        }
        section += "\(Self.endMarker)\n"

        content += section

        // Write atomically
        try? content.write(toFile: hostsPath, atomically: true, encoding: .utf8)
    }

    private func removeHostsEntries() {
        guard var content = try? String(contentsOfFile: hostsPath, encoding: .utf8) else { return }
        if let startRange = content.range(of: Self.marker),
           let endRange = content.range(of: Self.endMarker) {
            let removeEnd = content.index(after: endRange.upperBound)
            content.removeSubrange(startRange.lowerBound..<min(removeEnd, content.endIndex))
            try? content.write(toFile: hostsPath, atomically: true, encoding: .utf8)
        }
    }
}
