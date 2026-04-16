import Foundation
import os.log

/// Prevents C2 callbacks by sinkholing malicious domains to localhost.
/// Writes entries to /etc/hosts that redirect threat-intel domains to 127.0.0.1.
public actor DNSSinkhole {

    /// MITRE D3FEND defensive technique this module implements.
    public nonisolated static let d3fend = D3FENDMapping.dnsSinkhole
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

    /// Verify that `path` is a regular file (or does not yet exist) and is NOT
    /// a symlink.  Returns `false` if a symlink is detected — writing through a
    /// symlink while running as root would let an attacker redirect the write to
    /// an arbitrary file.
    private func isNotSymlink(_ path: String) -> Bool {
        let fm = FileManager.default
        var isDir: ObjCBool = false
        guard fm.fileExists(atPath: path, isDirectory: &isDir) else {
            return true  // File doesn't exist yet — safe to create
        }
        // Use lstat (attributesOfItem) which does NOT follow symlinks.
        guard let attrs = try? fm.attributesOfItem(atPath: path),
              let fileType = attrs[.type] as? FileAttributeType else {
            return false
        }
        return fileType != .typeSymbolicLink
    }

    private func writeHostsFile() {
        let fm = FileManager.default
        guard fm.isWritableFile(atPath: hostsPath) else {
            logger.warning("Cannot write to /etc/hosts (need root)")
            return
        }

        guard isNotSymlink(hostsPath) else {
            logger.error("Refusing to write: \(self.hostsPath) is a symlink (possible attack)")
            return
        }

        // Read existing hosts file
        guard var content = try? String(contentsOfFile: hostsPath, encoding: .utf8) else { return }

        // Remove any existing MacCrab section
        if let startRange = content.range(of: Self.marker),
           let endRange = content.range(of: Self.endMarker) {
            // Safe upper bound: clamp to content.endIndex to avoid out-of-bounds
            let removeEnd = endRange.upperBound < content.endIndex
                ? content.index(after: endRange.upperBound)
                : content.endIndex
            content.removeSubrange(startRange.lowerBound..<removeEnd)
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
        do {
            try content.write(toFile: hostsPath, atomically: true, encoding: .utf8)
        } catch {
            logger.error("Failed to write sinkhole entries to \(self.hostsPath): \(error.localizedDescription)")
        }
    }

    private func removeHostsEntries() {
        guard isNotSymlink(hostsPath) else {
            logger.error("Refusing to write: \(self.hostsPath) is a symlink (possible attack)")
            return
        }
        guard var content = try? String(contentsOfFile: hostsPath, encoding: .utf8) else { return }
        if let startRange = content.range(of: Self.marker),
           let endRange = content.range(of: Self.endMarker) {
            let removeEnd = endRange.upperBound < content.endIndex
                ? content.index(after: endRange.upperBound)
                : content.endIndex
            content.removeSubrange(startRange.lowerBound..<removeEnd)
            do {
                try content.write(toFile: hostsPath, atomically: true, encoding: .utf8)
            } catch {
                logger.error("Failed to clean sinkhole entries from \(self.hostsPath): \(error.localizedDescription)")
            }
        }
    }
}
